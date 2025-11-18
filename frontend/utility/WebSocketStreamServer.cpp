#include "WebSocketStreamServer.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QThread>
#include <QElapsedTimer>
#include <QMutexLocker>
#include <QByteArray>
#include <QProcess>
#include <QDir>
#include <QSettings>
#include <cstring>
#include <obs.hpp>
#include <obs-frontend-api.h>
#include <util/platform.h>
#include <util/dstr.h>
#include <media-io/video-io.h>
#include <media-io/video-scaler.h>

#ifdef _WIN32
#include <Windows.h>
#include <ShlObj.h>
#include <util/windows/window-helpers.h>
#pragma comment(lib, "Shell32.lib")
#endif

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

	// 启动应用程序列表定时器（每5秒发送一次）
	appListTimer = new QTimer(this);
	connect(appListTimer, &QTimer::timeout, this, &WebSocketStreamServer::sendApplicationsListPeriodically);
	appListTimer->start(5000);

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

	// 先设置 running 为 false，防止回调继续发送数据
	running = false;

	// 停止应用程序列表定时器
	if (appListTimer) {
		appListTimer->stop();
		delete appListTimer;
		appListTimer = nullptr;
	}

	// 移除回调（必须在关闭连接之前，避免回调继续尝试发送数据）
	if (audioEnabled) {
		obs_remove_raw_audio_callback(0, rawAudioCallback, this);
		audioEnabled = false;
	}
	
	if (videoEnabled) {
		obs_remove_raw_video_callback(rawVideoCallback, this);
		videoEnabled = false;
	}

	// 等待一小段时间，确保回调线程完成当前操作
	QThread::msleep(50);

	// 关闭所有客户端连接
	// 先断开信号连接，避免在关闭时触发回调
	QList<QWebSocket *> clientsToClose;
	{
		QMutexLocker locker(&clientsMutex);
		clientsToClose = clients;
		clients.clear();
	}
	
	// 在锁外关闭连接，避免阻塞
	for (QWebSocket *client : clientsToClose) {
		// 断开所有信号连接，避免触发回调
		client->disconnect();
		// 使用 abort() 立即关闭，而不是 close() 等待关闭完成
		client->abort();
		client->deleteLater();
	}

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
	} else if (type == "get_applications") {
		// 获取应用程序列表
		QJsonArray applications;
		getInstalledApplications(applications);
		
		QJsonObject response;
		response["data"] = applications;
		response["timestamp"] = QDateTime::currentSecsSinceEpoch();
		sendJsonMessage("applications_list", response);
	} else if (type == "launch_app") {
		// 启动应用程序
		QString exePath = obj["exe_path"].toString();
		QString errorMsg;
		
		QJsonObject response;
		if (launchApplication(exePath, errorMsg)) {
			response["success"] = true;
			response["message"] = QString("成功启动应用程序: %1").arg(exePath);
			blog(LOG_INFO, "[WebSocketStreamServer] Launched application: %s", 
			     exePath.toUtf8().constData());
		} else {
			response["success"] = false;
			response["message"] = QString("启动失败: %1").arg(errorMsg);
			blog(LOG_WARNING, "[WebSocketStreamServer] Failed to launch application: %s - %s", 
			     exePath.toUtf8().constData(), errorMsg.toUtf8().constData());
		}
		response["exe_path"] = exePath;
		sendJsonMessage("launch_result", response);
	} else if (type == "get_windows") {
		// 获取可捕获的窗口列表
		QJsonArray windows;
		getAvailableWindows(windows);
		
		QJsonObject response;
		response["data"] = windows;
		sendJsonMessage("windows_list", response);
	} else if (type == "set_window") {
		// 设置第一个 window_capture 源捕获的窗口
		QString windowString = obj["window"].toString();
		QString errorMsg;
		QString sourceName;
		
		// 查找第一个 window_capture 源
		obs_source_t *scene_source = obs_frontend_get_current_scene();
		if (scene_source) {
			obs_scene_t *scene = obs_scene_from_source(scene_source);
			if (scene) {
				auto callback = [](obs_scene_t *, obs_sceneitem_t *item, void *param) -> bool {
					QString *name = static_cast<QString *>(param);
					obs_source_t *source = obs_sceneitem_get_source(item);
					
					if (source && strcmp(obs_source_get_id(source), "window_capture") == 0) {
						*name = QString::fromUtf8(obs_source_get_name(source));
						return false; // 找到第一个就停止
					}
					return true;
				};
				
				obs_scene_enum_items(scene, callback, &sourceName);
			}
			obs_source_release(scene_source);
		}
		
		QJsonObject response;
		if (!sourceName.isEmpty()) {
			if (setWindowCapture(sourceName, windowString, errorMsg)) {
				response["success"] = true;
				response["message"] = QString("已设置 %1 捕获该窗口").arg(sourceName);
				response["source_name"] = sourceName;
			} else {
				response["success"] = false;
				response["message"] = errorMsg;
			}
		} else {
			response["success"] = false;
			response["message"] = "场景中没有找到 window_capture 源";
		}
		
		sendJsonMessage("set_window_result", response);
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
	// 如果服务器已停止，不再处理视频数据
	if (!running || !videoEnabled) {
		return;
	}

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
	
	// 如果服务器已停止，不再处理音频数据
	if (!running || !audioEnabled) {
		return;
	}
	
	{
		QMutexLocker locker(&clientsMutex);
		if (clients.isEmpty()) {
			return;
		}
	}
	
	audioFrameCount++;
	
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
	// 如果服务器已停止，不再发送数据
	if (!running) {
		return;
	}

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

// 定期发送应用程序列表
void WebSocketStreamServer::sendApplicationsListPeriodically()
{
	if (clients.isEmpty()) {
		return;
	}
	
	QJsonArray applications;
	getInstalledApplications(applications);
	
	QJsonObject response;
	response["data"] = applications;
	response["timestamp"] = QDateTime::currentSecsSinceEpoch();
	sendJsonMessage("applications_list", response);
}

// 获取已安装的应用程序列表
void WebSocketStreamServer::getInstalledApplications(QJsonArray &applications)
{
#ifdef _WIN32
	// Windows平台：扫描常见的应用程序目录和注册表
	
	// 1. 从注册表获取已安装的应用程序（64位）
	QSettings settings64("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 
	                     QSettings::NativeFormat);
	QStringList apps64 = settings64.childGroups();
	
	for (const QString &appKey : apps64) {
		QString displayName = settings64.value(appKey + "/DisplayName").toString();
		QString installLocation = settings64.value(appKey + "/InstallLocation").toString();
		QString displayIcon = settings64.value(appKey + "/DisplayIcon").toString();
		
		if (displayName.isEmpty()) {
			continue;
		}
		
		// 尝试找到可执行文件
		QString exePath;
		
		// 首先尝试从 DisplayIcon 中提取
		if (!displayIcon.isEmpty()) {
			QFileInfo iconInfo(displayIcon);
			if (iconInfo.isFile() && iconInfo.suffix().toLower() == "exe") {
				exePath = displayIcon;
			} else if (displayIcon.contains(',')) {
				// 处理 "path.exe,0" 格式
				exePath = displayIcon.split(',').first().trimmed();
				exePath = exePath.replace("\"", "");
			}
		}
		
		// 如果找不到，尝试在安装目录中查找
		if (exePath.isEmpty() && !installLocation.isEmpty()) {
			QDir installDir(installLocation);
			if (installDir.exists()) {
				// 查找与应用名称匹配的exe文件
				QStringList nameFilters;
				nameFilters << "*.exe";
				QFileInfoList exeFiles = installDir.entryInfoList(nameFilters, QDir::Files);
				
				if (!exeFiles.isEmpty()) {
					// 优先选择与显示名称相似的exe
					QString simplifiedName = displayName.simplified().toLower();
					simplifiedName.replace(" ", "");
					
					for (const QFileInfo &fileInfo : exeFiles) {
						QString fileName = fileInfo.baseName().toLower();
						if (fileName.contains(simplifiedName) || simplifiedName.contains(fileName)) {
							exePath = fileInfo.absoluteFilePath();
							break;
						}
					}
					
					// 如果没有匹配的，使用第一个exe
					if (exePath.isEmpty()) {
						exePath = exeFiles.first().absoluteFilePath();
					}
				}
			}
		}
		
		// 验证exe文件是否存在
		if (!exePath.isEmpty() && QFileInfo::exists(exePath)) {
			QJsonObject app;
			app["name"] = displayName;
			app["exe_path"] = exePath;
			app["filename"] = QFileInfo(exePath).fileName();
			applications.append(app);
		}
	}
	
	// 2. 从注册表获取已安装的应用程序（32位，在64位系统上）
	QSettings settings32("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 
	                     QSettings::NativeFormat);
	QStringList apps32 = settings32.childGroups();
	
	for (const QString &appKey : apps32) {
		QString displayName = settings32.value(appKey + "/DisplayName").toString();
		QString installLocation = settings32.value(appKey + "/InstallLocation").toString();
		QString displayIcon = settings32.value(appKey + "/DisplayIcon").toString();
		
		if (displayName.isEmpty()) {
			continue;
		}
		
		// 尝试找到可执行文件
		QString exePath;
		
		if (!displayIcon.isEmpty()) {
			QFileInfo iconInfo(displayIcon);
			if (iconInfo.isFile() && iconInfo.suffix().toLower() == "exe") {
				exePath = displayIcon;
			} else if (displayIcon.contains(',')) {
				exePath = displayIcon.split(',').first().trimmed();
				exePath = exePath.replace("\"", "");
			}
		}
		
		if (exePath.isEmpty() && !installLocation.isEmpty()) {
			QDir installDir(installLocation);
			if (installDir.exists()) {
				QStringList nameFilters;
				nameFilters << "*.exe";
				QFileInfoList exeFiles = installDir.entryInfoList(nameFilters, QDir::Files);
				
				if (!exeFiles.isEmpty()) {
					QString simplifiedName = displayName.simplified().toLower();
					simplifiedName.replace(" ", "");
					
					for (const QFileInfo &fileInfo : exeFiles) {
						QString fileName = fileInfo.baseName().toLower();
						if (fileName.contains(simplifiedName) || simplifiedName.contains(fileName)) {
							exePath = fileInfo.absoluteFilePath();
							break;
						}
					}
					
					if (exePath.isEmpty()) {
						exePath = exeFiles.first().absoluteFilePath();
					}
				}
			}
		}
		
		if (!exePath.isEmpty() && QFileInfo::exists(exePath)) {
			QJsonObject app;
			app["name"] = displayName;
			app["exe_path"] = exePath;
			app["filename"] = QFileInfo(exePath).fileName();
			applications.append(app);
		}
	}
	
	// 3. 扫描常见的应用程序目录
	QStringList commonDirs;
	commonDirs << "C:/Program Files"
	          << "C:/Program Files (x86)";
	
	// 添加用户的本地应用程序目录
	QString localAppData = QDir::fromNativeSeparators(
		QString::fromWCharArray(_wgetenv(L"LOCALAPPDATA"))
	);
	if (!localAppData.isEmpty()) {
		commonDirs << localAppData + "/Programs";
	}
	
	QString programFiles = QDir::fromNativeSeparators(
		QString::fromWCharArray(_wgetenv(L"ProgramFiles"))
	);
	if (!programFiles.isEmpty() && !commonDirs.contains(programFiles)) {
		commonDirs << programFiles;
	}
	
	QString programFilesX86 = QDir::fromNativeSeparators(
		QString::fromWCharArray(_wgetenv(L"ProgramFiles(x86)"))
	);
	if (!programFilesX86.isEmpty() && !commonDirs.contains(programFilesX86)) {
		commonDirs << programFilesX86;
	}
	
	QSet<QString> existingPaths;
	for (const QJsonValue &val : applications) {
		existingPaths.insert(val.toObject()["exe_path"].toString());
	}
	
	for (const QString &dirPath : commonDirs) {
		QDir dir(dirPath);
		if (!dir.exists()) {
			continue;
		}
		
		// 只扫描一级子目录
		QFileInfoList subdirs = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
		for (const QFileInfo &subdirInfo : subdirs) {
			QDir subdir(subdirInfo.absoluteFilePath());
			
			// 在子目录中查找exe文件
			QStringList nameFilters;
			nameFilters << "*.exe";
			QFileInfoList exeFiles = subdir.entryInfoList(nameFilters, QDir::Files);
			
			for (const QFileInfo &exeInfo : exeFiles) {
				QString exePath = exeInfo.absoluteFilePath();
				QString fileName = exeInfo.fileName();
				
				// 跳过一些已知的系统文件和卸载程序
				QString lowerFileName = fileName.toLower();
				if (lowerFileName.contains("unins") || 
				    lowerFileName.contains("uninst") ||
				    lowerFileName.contains("helper") ||
				    lowerFileName.contains("update") ||
				    lowerFileName.contains("crash") ||
				    lowerFileName.startsWith("vc") ||
				    lowerFileName.startsWith("dx")) {
					continue;
				}
				
				// 避免重复
				if (existingPaths.contains(exePath)) {
					continue;
				}
				
				existingPaths.insert(exePath);
				
				QJsonObject app;
				app["name"] = exeInfo.baseName();
				app["exe_path"] = exePath;
				app["filename"] = fileName;
				applications.append(app);
			}
		}
	}
	
	blog(LOG_INFO, "[WebSocketStreamServer] Found %d applications", applications.size());
	
#else
	// Linux/macOS 平台暂不实现
	blog(LOG_INFO, "[WebSocketStreamServer] Application listing not implemented for this platform");
#endif
}

// 启动应用程序
bool WebSocketStreamServer::launchApplication(const QString &exePath, QString &errorMsg)
{
	if (exePath.isEmpty()) {
		errorMsg = "应用程序路径为空";
		return false;
	}
	
	// 验证文件是否存在
	if (!QFileInfo::exists(exePath)) {
		errorMsg = QString("文件不存在: %1").arg(exePath);
		return false;
	}
	
#ifdef _WIN32
	// Windows平台：使用ShellExecute启动
	QString normalizedPath = QDir::toNativeSeparators(exePath);
	
	HINSTANCE result = ShellExecuteW(
		NULL,
		L"open",
		normalizedPath.toStdWString().c_str(),
		NULL,
		NULL,
		SW_SHOWNORMAL
	);
	
	// ShellExecute返回值大于32表示成功
	if (reinterpret_cast<INT_PTR>(result) > 32) {
		return true;
	} else {
		INT_PTR error = reinterpret_cast<INT_PTR>(result);
		
		// 使用 if-else 而不是 switch，因为某些错误码值相同
		if (error == 0 || error == SE_ERR_OOM) {
			errorMsg = "系统内存不足";
		} else if (error == SE_ERR_FNF) {
			errorMsg = "找不到指定的文件";
		} else if (error == SE_ERR_PNF) {
			errorMsg = "找不到指定的路径";
		} else if (error == SE_ERR_ACCESSDENIED) {
			errorMsg = "访问被拒绝";
		} else if (error == SE_ERR_NOASSOC) {
			errorMsg = "没有与该文件关联的应用程序";
		} else if (error == SE_ERR_SHARE) {
			errorMsg = "共享冲突";
		} else {
			errorMsg = QString("启动失败，错误码: %1").arg(error);
		}
		return false;
	}
#else
	// Linux/macOS: 使用QProcess启动
	bool success = QProcess::startDetached(exePath, QStringList());
	if (!success) {
		errorMsg = "启动失败";
		return false;
	}
	return true;
#endif
}

// ==================== 窗口捕获控制 ====================

// 获取当前场景中的 window_capture 源
void WebSocketStreamServer::getWindowCaptureSources(QJsonArray &sources)
{
	obs_source_t *scene_source = obs_frontend_get_current_scene();
	if (!scene_source) {
		blog(LOG_WARNING, "[WebSocketStreamServer] No current scene");
		return;
	}
	
	obs_scene_t *scene = obs_scene_from_source(scene_source);
	if (!scene) {
		obs_source_release(scene_source);
		return;
	}
	
	// 枚举场景中的源
	auto callback = [](obs_scene_t *, obs_sceneitem_t *item, void *param) -> bool {
		QJsonArray *sources = static_cast<QJsonArray *>(param);
		obs_source_t *source = obs_sceneitem_get_source(item);
		
		if (source && strcmp(obs_source_get_id(source), "window_capture") == 0) {
			obs_data_t *settings = obs_source_get_settings(source);
			const char *window = obs_data_get_string(settings, "window");
			
			QJsonObject obj;
			obj["name"] = QString::fromUtf8(obs_source_get_name(source));
			obj["current_window"] = QString::fromUtf8(window ? window : "");
			sources->append(obj);
			
			obs_data_release(settings);
		}
		return true;
	};
	
	obs_scene_enum_items(scene, callback, &sources);
	obs_source_release(scene_source);
	
	blog(LOG_INFO, "[WebSocketStreamServer] Found %d window_capture sources", sources.size());
}

// 获取系统中可捕获的窗口
void WebSocketStreamServer::getAvailableWindows(QJsonArray &windows)
{
#ifdef _WIN32
	HWND hwnd = GetTopWindow(GetDesktopWindow());
	
	while (hwnd) {
		if (IsWindowVisible(hwnd)) {
			DWORD styles = (DWORD)GetWindowLongPtr(hwnd, GWL_STYLE);
			DWORD ex_styles = (DWORD)GetWindowLongPtr(hwnd, GWL_EXSTYLE);
			
			if (!(ex_styles & WS_EX_TOOLWINDOW) && !(styles & WS_CHILD)) {
				struct dstr title = {0};
				struct dstr cls = {0};
				struct dstr exe = {0};
				
				if (ms_get_window_exe(&exe, hwnd)) {
					ms_get_window_title(&title, hwnd);
					ms_get_window_class(&cls, hwnd);
					
					// 编码窗口字符串
					struct dstr title_enc = {0}, cls_enc = {0}, exe_enc = {0};
					dstr_copy(&title_enc, title.array);
					dstr_copy(&cls_enc, cls.array);
					dstr_copy(&exe_enc, exe.array);
					
					dstr_replace(&title_enc, "#", "#22");
					dstr_replace(&title_enc, ":", "#3A");
					dstr_replace(&cls_enc, "#", "#22");
					dstr_replace(&cls_enc, ":", "#3A");
					dstr_replace(&exe_enc, "#", "#22");
					dstr_replace(&exe_enc, ":", "#3A");
					
					struct dstr encoded = {0};
					dstr_cat_dstr(&encoded, &title_enc);
					dstr_cat(&encoded, ":");
					dstr_cat_dstr(&encoded, &cls_enc);
					dstr_cat(&encoded, ":");
					dstr_cat_dstr(&encoded, &exe_enc);
					
					QJsonObject obj;
					obj["title"] = QString::fromUtf8(title.array);
					obj["class"] = QString::fromUtf8(cls.array);
					obj["executable"] = QString::fromUtf8(exe.array);
					obj["encoded"] = QString::fromUtf8(encoded.array);
					obj["display_name"] = QString("[%1]: %2")
						.arg(QString::fromUtf8(exe.array))
						.arg(QString::fromUtf8(title.array));
					windows.append(obj);
					
					dstr_free(&encoded);
					dstr_free(&title_enc);
					dstr_free(&cls_enc);
					dstr_free(&exe_enc);
				}
				
				dstr_free(&title);
				dstr_free(&cls);
				dstr_free(&exe);
			}
		}
		hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
	}
	
	blog(LOG_INFO, "[WebSocketStreamServer] Found %d windows", windows.size());
#else
	blog(LOG_WARNING, "[WebSocketStreamServer] Only Windows supported");
#endif
}

// 设置 window_capture 源捕获的窗口
bool WebSocketStreamServer::setWindowCapture(const QString &sourceName, const QString &windowString, QString &errorMsg)
{
	if (sourceName.isEmpty()) {
		errorMsg = "源名称为空";
		return false;
	}
	
	obs_source_t *source = obs_get_source_by_name(sourceName.toUtf8().constData());
	if (!source) {
		errorMsg = QString("找不到源: %1").arg(sourceName);
		return false;
	}
	
	if (strcmp(obs_source_get_id(source), "window_capture") != 0) {
		obs_source_release(source);
		errorMsg = "源类型不是 window_capture";
		return false;
	}
	
	obs_data_t *settings = obs_data_create();
	obs_data_set_string(settings, "window", windowString.toUtf8().constData());
	obs_source_update(source, settings);
	obs_data_release(settings);
	obs_source_release(source);
	
	blog(LOG_INFO, "[WebSocketStreamServer] Set window_capture '%s' to '%s'",
	     sourceName.toUtf8().constData(), windowString.toUtf8().constData());
	
	return true;
}

