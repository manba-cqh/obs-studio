#include "OBSBasic.hpp"
#include "OBSBasicControls.hpp"
#include <QMessageBox>
#include <utility/WebSocketStreamServer.hpp>

void OBSBasic::StartWebSocketStreamServer(quint16 port)
{
	if (wsStreamServer && wsStreamServer->isRunning()) {
		blog(LOG_INFO, "WebSocket Stream Server is already running");
		return;
	}

	if (!wsStreamServer) {
		wsStreamServer = std::make_unique<WebSocketStreamServer>(this);
		
		// 连接信号
		connect(wsStreamServer.get(), &WebSocketStreamServer::serverStarted,
			[this](quint16 p) {
				blog(LOG_INFO, "WebSocket Stream Server started on port %d", p);
				
				// 更新按钮状态
				OBSBasicControls *controls = (OBSBasicControls *)controlsDock->widget();
				if (controls) {
					controls->WebSocketServerStarted();
				}
				
				QMessageBox::information(
					this, "WebSocket Stream",
					QString("WebSocket服务器已启动\n端口: %1\n\n"
						"在web_client_sync.html中连接到:\n"
						"ws://localhost:%1")
						.arg(p));
			});
		
		connect(wsStreamServer.get(), &WebSocketStreamServer::serverStopped,
			[this]() {
				blog(LOG_INFO, "WebSocket Stream Server stopped");
				
				// 更新按钮状态
				OBSBasicControls *controls = (OBSBasicControls *)controlsDock->widget();
				if (controls) {
					controls->WebSocketServerStopped();
				}
			});
		
		connect(wsStreamServer.get(), &WebSocketStreamServer::error,
			[this](QString err) {
				blog(LOG_ERROR, "WebSocket Stream Server error: %s",
				     err.toUtf8().constData());
				QMessageBox::warning(this, "WebSocket Stream Error", err);
			});
		
		connect(wsStreamServer.get(), &WebSocketStreamServer::clientConnected,
			[](QString addr) {
				blog(LOG_INFO, "WebSocket client connected: %s",
				     addr.toUtf8().constData());
			});
		
		connect(wsStreamServer.get(), &WebSocketStreamServer::clientDisconnected,
			[](QString addr) {
				blog(LOG_INFO, "WebSocket client disconnected: %s",
				     addr.toUtf8().constData());
			});
	}

	if (!wsStreamServer->start(port)) {
		blog(LOG_ERROR, "Failed to start WebSocket Stream Server");
		QMessageBox::critical(this, "WebSocket Stream Error",
				      "Failed to start WebSocket server on port " +
					      QString::number(port));
	}
}

void OBSBasic::StopWebSocketStreamServer()
{
	if (wsStreamServer) {
		wsStreamServer->stop();
	}
}

bool OBSBasic::IsWebSocketStreamServerRunning() const
{
	return wsStreamServer && wsStreamServer->isRunning();
}

void OBSBasic::WebSocketButtonClicked()
{
	if (IsWebSocketStreamServerRunning()) {
		StopWebSocketStreamServer();
	} else {
		StartWebSocketStreamServer(8765);
	}
}

