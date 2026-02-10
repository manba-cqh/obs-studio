#pragma once

#include <QVBoxLayout>
#include <QMainWindow>
#include <QDockWidget>
#include <QStackedWidget>

#include <widgets/OBSBasicPreview.hpp>
#include <widgets/OBSBasic.hpp>

#include "def.h"

class QMenu;
class TopBar;
class ScenePanel;
class InteractPanel;
class PreviewHeader;
class AudioMixPanel;
class BroadcastModePanel;
class PluginPanel;
class DanmuPanel;
class ConfigWt;
class EmptySceneWidget;
class DirectorWidget;

class CometMainWindow : public QMainWindow
{
	Q_OBJECT

public:
	CometMainWindow(QWidget *parent = nullptr);
	~CometMainWindow();

protected:
	virtual void resizeEvent(QResizeEvent *event) override;
	virtual void changeEvent(QEvent *event) override;
	virtual void mousePressEvent(QMouseEvent *event) override;
	virtual void mouseMoveEvent(QMouseEvent *event) override;
	virtual void mouseReleaseEvent(QMouseEvent *event) override;
	virtual bool eventFilter(QObject *obj, QEvent *event) override;
	virtual QMenu *createPopupMenu() override;

private slots:
	void onPreviewContextMenuRequested();
	void onPreviewResized();

private:
	void initUI();
	void createMainContent();
	static void RenderPreview(void *data, uint32_t cx, uint32_t cy);
	static void RenderMain(void *data, uint32_t cx, uint32_t cy);
	
	ResizeEdge getResizeEdge(const QPoint &pos) const;
	void updateCursor(ResizeEdge edge);
	void resizeWindow(const QPoint &delta, ResizeEdge edge);
	
	void updatePreviewDisplay();
	bool hasSceneItems();
	void setBroadcastMode(bool enabled);

private:
	// 顶部栏
	QToolBar *m_titleBarToolBar;
	TopBar *m_topBar;

	// 主内容
	QWidget *m_mainContent;

	// 场景面板
	QDockWidget *m_scenePanelDock;
	ScenePanel *m_scenePanel;
	// 互动玩法面板
	QDockWidget *m_interactPanelDock;
	InteractPanel *m_interactPanel;

	// 预览头部
	PreviewHeader *m_previewHeader;
	// 预览控件容器（使用 QStackedWidget 切换预览、空场景界面和导播界面）
	QStackedWidget *m_previewStack;
	// 预览控件
	OBSBasicPreview *m_previewWidget;
	// 空场景界面
	EmptySceneWidget *m_emptySceneWidget;
	// 导播界面
	DirectorWidget *m_directorWidget;
	// 混音器面板
	QDockWidget *m_audioMixPanelDock;
	AudioMixPanel *m_audioMixPanel;
	// 开播模式面板
	QDockWidget *m_broadcastModePanelDock;
	BroadcastModePanel *m_broadcastModePanel;

	// 插件面板
	QDockWidget *m_pluginPanelDock;
	PluginPanel *m_pluginPanel;
	// 弹幕面板
	QDockWidget *m_danmuPanelDock;
	DanmuPanel *m_danmuPanel;

	// 设置窗口
	ConfigWt *m_configWt;
	
	// 窗口大小调整
	bool m_isResizing;
	ResizeEdge m_resizeEdge;
	QPoint m_resizeStartPos;
	QRect m_resizeStartGeometry;
};