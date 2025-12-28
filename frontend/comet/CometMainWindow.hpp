#pragma once

#include <QVBoxLayout>
#include <QMainWindow>
#include <QDockWidget>

#include <widgets/OBSBasicPreview.hpp>
#include <widgets/OBSBasic.hpp>

#include "def.h"

class TopBar;
class ScenePanel;
class InteractPanel;
class PreviewHeader;
class AudioMixPanel;

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

private slots:
	void onPreviewContextMenuRequested();
	void onPreviewResized();

private:
	void initUI();
	void createMainContent();
	static void RenderPreview(void *data, uint32_t cx, uint32_t cy);
	
	ResizeEdge getResizeEdge(const QPoint &pos) const;
	void updateCursor(ResizeEdge edge);
	void resizeWindow(const QPoint &delta, ResizeEdge edge);

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
	// 预览控件
	OBSBasicPreview *m_previewWidget;
	// 混音器面板
	AudioMixPanel *m_audioMixPanel;
	
	// 窗口大小调整
	bool m_isResizing;
	ResizeEdge m_resizeEdge;
	QPoint m_resizeStartPos;
	QRect m_resizeStartGeometry;
};