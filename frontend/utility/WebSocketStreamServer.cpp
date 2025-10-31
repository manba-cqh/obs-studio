#include "WebSocketStreamServer.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QThread>
#include <QElapsedTimer>
#include <QMutexLocker>
#include <QByteArray>
#include <cstring>
#include <obs.hpp>
#include <util/platform.h>
#include <media-io/video-io.h>
#include <media-io/video-scaler.h>

WebSocketStreamServer::WebSocketStreamServer(QObject *parent)
	: QObject(parent),
	  server(nullptr),
	  running(false),
	  audioEnabled(false),
	  videoEnabled(false),
	  audioFrameCount(0),
	  videoFrameCount(0)
{
	jpegCompressor = tjInitCompress();
	if (!jpegCompressor) {
		blog(LOG_ERROR, "[WebSocketStreamServer] Failed to init TurboJPEG: %s", tjGetErrorStr());
	}
}

WebSocketStreamServer::~WebSocketStreamServer()
{
	stop();
	if (jpegCompressor) {
		tjDestroy(jpegCompressor);
		jpegCompressor = nullptr;
	}
}

bool WebSocketStreamServer::start(quint16 port)
{
	if (running) {
		return true;
	}

	server = new QWebSocketServer(
		QStringLiteral("OBS WebSocket Stream Server"),
		QWebSocketServer::NonSecureMode, this);

	if (!server->listen(QHostAddress::Any, port)) {
		QString errorStr = server->errorString();
		emit error(errorStr);
		delete server;
		server = nullptr;
		return false;
	}

	connect(server, &QWebSocketServer::newConnection, this,
		&WebSocketStreamServer::onNewConnection);

	running = true;
	
	// 注册音频回调
	obs_add_raw_audio_callback(0, nullptr, rawAudioCallback, this);
	audioEnabled = true;
	
	// 注册视频回调
	obs_add_raw_video_callback(nullptr, rawVideoCallback, this);
	videoEnabled = true;

	blog(LOG_INFO, "[WebSocketStreamServer] Server started on port %d",
	     port);
	emit serverStarted(port);

	return true;
}

void WebSocketStreamServer::stop()
{
	if (!running) {
		return;
	}

	// 移除回调
	if (audioEnabled) {
		obs_remove_raw_audio_callback(0, rawAudioCallback, this);
		audioEnabled = false;
	}
	
	if (videoEnabled) {
		obs_remove_raw_video_callback(rawVideoCallback, this);
		videoEnabled = false;
	}

	// 关闭所有客户端连接
	QMutexLocker locker(&clientsMutex);
	for (QWebSocket *client : clients) {
		client->close();
		client->deleteLater();
	}
	clients.clear();
	locker.unlock();

	if (server) {
		server->close();
		server->deleteLater();
		server = nullptr;
	}

	if (videoScaler) {
		video_scaler_destroy(videoScaler);
		videoScaler = nullptr;
	}
	videoBuffer.clear();
	jpegBuffer.clear();
	videoWidth = videoHeight = 0;
	videoSourceFormat = VIDEO_FORMAT_NONE;
	videoSourceColorspace = VIDEO_CS_DEFAULT;
	videoSourceRange = VIDEO_RANGE_DEFAULT;

	running = false;
	blog(LOG_INFO, "[WebSocketStreamServer] Server stopped");
	emit serverStopped();
}

void WebSocketStreamServer::onNewConnection()
{
	QWebSocket *client = server->nextPendingConnection();
	if (!client) {
		return;
	}

	connect(client, &QWebSocket::textMessageReceived, this,
		&WebSocketStreamServer::onTextMessageReceived);
	connect(client, &QWebSocket::binaryMessageReceived, this,
		&WebSocketStreamServer::onBinaryMessageReceived);
	connect(client, &QWebSocket::disconnected, this,
		&WebSocketStreamServer::onClientDisconnected);

	QMutexLocker locker(&clientsMutex);
	clients.append(client);
	locker.unlock();

	QString address = client->peerAddress().toString();
	blog(LOG_INFO, "[WebSocketStreamServer] Client connected: %s",
	     address.toUtf8().constData());
	emit clientConnected(address);

	// 发送连接确认消息
	QJsonObject obj;
	obj["message"] = "Connected to OBS WebSocket Stream Server";
	sendJsonMessage("connection", obj);
}

void WebSocketStreamServer::onTextMessageReceived(QString message)
{
	blog(LOG_DEBUG, "[WebSocketStreamServer] Received message: %s",
	     message.toUtf8().constData());
	emit messageReceived(message);

	// 解析消息
	QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8());
	if (!doc.isObject()) {
		return;
	}

	QJsonObject obj = doc.object();
	QString type = obj["type"].toString();

	if (type == "start_audio") {
		// 已经在 start() 中启动
		QJsonObject response;
		sendJsonMessage("audio_started", response);
	} else if (type == "stop_audio") {
		QJsonObject response;
		sendJsonMessage("audio_stopped", response);
	}
}

void WebSocketStreamServer::onBinaryMessageReceived(QByteArray data)
{
	Q_UNUSED(data);
}

void WebSocketStreamServer::onClientDisconnected()
{
	QWebSocket *client = qobject_cast<QWebSocket *>(sender());
	if (!client) {
		return;
	}

	QString address = client->peerAddress().toString();

	QMutexLocker locker(&clientsMutex);
	clients.removeAll(client);
	locker.unlock();

	client->deleteLater();

	blog(LOG_INFO, "[WebSocketStreamServer] Client disconnected: %s",
	     address.toUtf8().constData());
	emit clientDisconnected(address);
}

void WebSocketStreamServer::rawVideoCallback(void *param,
					      struct video_data *frame)
{
	WebSocketStreamServer *server =
		static_cast<WebSocketStreamServer *>(param);
	if (server) {
		server->handleRawVideo(frame);
	}
}

void WebSocketStreamServer::rawAudioCallback(void *param, size_t mix_idx,
					      struct audio_data *frames)
{
	WebSocketStreamServer *server =
		static_cast<WebSocketStreamServer *>(param);
	if (server) {
		server->handleRawAudio(mix_idx, frames);
	}
}

void WebSocketStreamServer::handleRawVideo(struct video_data *frame)
{
	videoFrameCount++;

	{
		QMutexLocker locker(&clientsMutex);
		if (clients.isEmpty()) {
			return;
		}
	}

	QElapsedTimer timer;
	timer.start();
	qint64 lastNs = 0;
	auto logStep = [&](const char *label) {
		qint64 nowNs = timer.nsecsElapsed();
		qint64 deltaNs = nowNs - lastNs;
		if (deltaNs <= 0) {
			deltaNs = (timer.elapsed() * 1000000LL) - lastNs;
		}
		double deltaMs = double(deltaNs) / 1000000.0;
		blog(LOG_DEBUG, "[WebSocketStreamServer] handleRawVideo step '%s' (frame #%llu) took %.3f ms",
		     label, videoFrameCount, deltaMs);
		lastNs = nowNs;
	};

	video_t *video = obs_get_video();
	const struct video_output_info *info = video_output_get_info(video);
	if (!info || !frame) {
		return;
	}
	logStep("fetch_info");

	bool needRecreateScaler = false;
	if (!videoScaler) {
		needRecreateScaler = true;
	} else if (videoWidth != info->width || videoHeight != info->height ||
		   videoSourceFormat != info->format ||
		   videoSourceColorspace != info->colorspace ||
		   videoSourceRange != info->range) {
		needRecreateScaler = true;
	}

	if (needRecreateScaler) {
		if (videoScaler) {
			video_scaler_destroy(videoScaler);
			videoScaler = nullptr;
		}

		videoWidth = info->width;
		videoHeight = info->height;
		videoSourceFormat = info->format;
		videoSourceColorspace = info->colorspace;
		videoSourceRange = info->range;

		struct video_scale_info src = {};
		src.format = info->format;
		src.width = info->width;
		src.height = info->height;
		src.range = info->range;
		src.colorspace = info->colorspace;

		struct video_scale_info dst = {};
		dst.format = VIDEO_FORMAT_RGBA;
		dst.width = info->width;
		dst.height = info->height;
		dst.range = VIDEO_RANGE_FULL;
		dst.colorspace = VIDEO_CS_SRGB;

		int ret = video_scaler_create(&videoScaler, &dst, &src, VIDEO_SCALE_DEFAULT);
		if (ret != VIDEO_SCALER_SUCCESS) {
			blog(LOG_ERROR, "[WebSocketStreamServer] Failed to create video scaler (%d)", ret);
			return;
		}

		videoBuffer.resize(videoWidth * videoHeight * 4);
		logStep("create_scaler");
	}

	if (!videoScaler) {
		return;
	}

	uint8_t *outputData[4] = {reinterpret_cast<uint8_t *>(videoBuffer.data()), nullptr, nullptr, nullptr};
	uint32_t outputLinesize[4] = {videoWidth * 4, 0, 0, 0};

	if (!video_scaler_scale(videoScaler, outputData, outputLinesize,
			       (const uint8_t *const *)frame->data,
			       frame->linesize)) {
		blog(LOG_WARNING, "[WebSocketStreamServer] video_scaler_scale failed");
		return;
	}
	logStep("scale_to_rgba");

	if (!jpegCompressor) {
		jpegCompressor = tjInitCompress();
		if (!jpegCompressor) {
			blog(LOG_ERROR, "[WebSocketStreamServer] TurboJPEG init failed: %s", tjGetErrorStr());
			return;
		}
	}

	unsigned long jpegSize = 0;
	unsigned char *jpegData = nullptr;
	int stride = int(outputLinesize[0]);
	int flags = TJFLAG_FASTDCT;
	int quality = 60;

	int tjResult = tjCompress2(jpegCompressor,
				       reinterpret_cast<unsigned char *>(videoBuffer.data()),
				       int(videoWidth),
				       stride,
				       int(videoHeight),
				       TJPF_RGBA,
				       &jpegData,
				       &jpegSize,
				       TJSAMP_420,
				       quality,
				       flags);

	if (tjResult != 0 || !jpegData || jpegSize == 0) {
		blog(LOG_WARNING, "[WebSocketStreamServer] TurboJPEG compression failed: %s", tjGetErrorStr());
		if (jpegData)
			tjFree(jpegData);
		return;
	}
	logStep("encode_jpeg");

	jpegBuffer.resize(qint64(jpegSize));
	std::memcpy(jpegBuffer.data(), jpegData, jpegSize);
	tjFree(jpegData);

	QByteArray base64Data = jpegBuffer.toBase64();
	logStep("encode_base64");

	QJsonObject obj;
	obj["width"] = int(videoWidth);
	obj["height"] = int(videoHeight);
	obj["format"] = QStringLiteral("jpeg");
	obj["data"] = QString::fromLatin1(base64Data);
	obj["size"] = int(jpegBuffer.size());
	obj["timestamp"] = double(frame->timestamp) / 1000000000.0;
	obj["frame_index"] = static_cast<qint64>(videoFrameCount);

	sendJsonMessage("frame", obj);
	logStep("send_json");

	qint64 totalNs = timer.nsecsElapsed();
	if (totalNs <= 0)
		totalNs = timer.elapsed() * 1000000LL;
	blog(LOG_DEBUG, "[WebSocketStreamServer] handleRawVideo frame #%llu total %.3f ms",
	     videoFrameCount, double(totalNs) / 1000000.0);
}

QString WebSocketStreamServer::encodeAudioToBase64(
	const struct audio_data *frames)
{
	// 获取音频参数
	const audio_output_info *info = audio_output_get_info(obs_get_audio());
	uint32_t channels = get_audio_channels(info->speakers);
	uint32_t sample_rate = info->samples_per_sec;
	
	// 转换为 PCM 16位立体声
	size_t samples = frames->frames * channels;
	QByteArray pcmData;
	pcmData.resize(samples * sizeof(int16_t));
	int16_t *output = reinterpret_cast<int16_t *>(pcmData.data());
	
	// 将 float 转换为 int16
	size_t idx = 0;
	for (size_t frame = 0; frame < frames->frames; frame++) {
		for (size_t ch = 0; ch < channels && ch < MAX_AUDIO_CHANNELS;
		     ch++) {
			if (frames->data[ch]) {
				const float *src =
					reinterpret_cast<const float *>(
						frames->data[ch]);
				float sample = src[frame];
				
				// 限制范围
				if (sample > 1.0f)
					sample = 1.0f;
				if (sample < -1.0f)
					sample = -1.0f;
				
				output[idx++] =
					static_cast<int16_t>(sample * 32767.0f);
			} else {
				output[idx++] = 0;
			}
		}
	}
	
	return pcmData.toBase64();
}

void WebSocketStreamServer::handleRawAudio(size_t mix_idx,
					    struct audio_data *frames)
{
	Q_UNUSED(mix_idx);
	
	if (!audioEnabled || clients.isEmpty()) {
		return;
	}
	
	audioFrameCount++;
	
	// 每30帧发送一次（避免发送太频繁）
	if (audioFrameCount % 30 != 0) {
		return;
	}
	
	// 获取音频参数
	const audio_output_info *info = audio_output_get_info(obs_get_audio());
	uint32_t channels = get_audio_channels(info->speakers);
	uint32_t sample_rate = info->samples_per_sec;
	
	// 编码为 Base64
	QString base64Data = encodeAudioToBase64(frames);
	
	// 创建 JSON 消息
	QJsonObject obj;
	obj["format"] = "pcm";
	obj["data"] = base64Data;
	obj["channels"] = static_cast<int>(channels);
	obj["rate"] = static_cast<int>(sample_rate);
	obj["chunk"] = static_cast<qint64>(frames->frames);
	obj["size"] = base64Data.length();
	obj["timestamp"] = QDateTime::currentMSecsSinceEpoch() / 1000.0;
	obj["sync_timestamp"] = frames->timestamp / 1000000000.0;
	
	sendJsonMessage("audio", obj);
}

void WebSocketStreamServer::sendToAllClients(const QByteArray &data)
{
	QMutexLocker locker(&clientsMutex);
	for (QWebSocket *client : clients) {
		if (client->isValid()) {
			qint64 num = client->sendTextMessage(QString::fromUtf8(data));
			if (num == -1) {
				blog(LOG_ERROR, "[WebSocketStreamServer] Failed to send message to client: %s",
					client->peerAddress().toString().toUtf8().constData());
			}
		}
		else {
		    blog(LOG_ERROR, "[WebSocketStreamServer] Client is not valid: %s",
			 client->peerAddress().toString().toUtf8().constData());
		}
	}
}

void WebSocketStreamServer::sendJsonMessage(const QString &type,
					     const QJsonObject &data)
{
	if (QThread::currentThread() != this->thread()) {
		QMetaObject::invokeMethod(this, [this, type, data]() {
			sendJsonMessage(type, data);
		}, Qt::QueuedConnection);
		return;
	}

	QJsonObject root;
	root["type"] = type;
	
	// 合并数据
	for (auto it = data.begin(); it != data.end(); ++it) {
		root[it.key()] = it.value();
	}
	
	QJsonDocument doc(root);
	sendToAllClients(doc.toJson(QJsonDocument::Compact));
}

