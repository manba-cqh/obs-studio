#pragma once

#include <QObject>
#include <QtWebSockets/QWebSocketServer>
#include <QWebSocket>
#include <QList>
#include <QMutex>
#include <QByteArray>
#include <obs.h>
#include <turbojpeg.h>

struct video_scaler;

class WebSocketStreamServer : public QObject {
	Q_OBJECT

public:
	explicit WebSocketStreamServer(QObject *parent = nullptr);
	~WebSocketStreamServer();

	bool start(quint16 port = 8765);
	void stop();
	
	bool isRunning() const { return running; }
	int clientCount() const { return clients.size(); }

signals:
	void clientConnected(QString address);
	void clientDisconnected(QString address);
	void messageReceived(QString message);
	void serverStarted(quint16 port);
	void serverStopped();
	void error(QString errorString);

private slots:
	void onNewConnection();
	void onTextMessageReceived(QString message);
	void onBinaryMessageReceived(QByteArray data);
	void onClientDisconnected();

private:
	// 音视频回调
	static void rawVideoCallback(void *param, struct video_data *frame);
	static void rawAudioCallback(void *param, size_t mix_idx, struct audio_data *frames);
	
	void handleRawVideo(struct video_data *frame);
	void handleRawAudio(size_t mix_idx, struct audio_data *frames);
	
	// 发送数据
	void sendToAllClients(const QByteArray &data);
	void sendJsonMessage(const QString &type, const QJsonObject &data);
	
	// Base64 编码
	QString encodeAudioToBase64(const struct audio_data *frames);
	
	QWebSocketServer *server;
	QList<QWebSocket *> clients;
	QMutex clientsMutex;
	
	bool running;
	bool audioEnabled;
	bool videoEnabled;
	
	// 统计
	quint64 audioFrameCount;
	quint64 videoFrameCount;

	// 视频转换缓存
	struct video_scaler *videoScaler = nullptr;
	QByteArray videoBuffer;
	uint32_t videoWidth = 0;
	uint32_t videoHeight = 0;
	enum video_format videoSourceFormat = VIDEO_FORMAT_NONE;
	enum video_colorspace videoSourceColorspace = VIDEO_CS_DEFAULT;
	enum video_range_type videoSourceRange = VIDEO_RANGE_DEFAULT;

	// JPEG 编码
	tjhandle jpegCompressor = nullptr;
	QByteArray jpegBuffer;
};

