#pragma once

#include <QVBoxLayout>
#include <QWidget>

#include <widgets/OBSBasicPreview.hpp>
#include <widgets/OBSBasic.hpp>

class TopBar;
class ScenePanel;
class InteractPanel;
class PreviewHeader;
class AudioMixPanel;

class CometMainWindow : public QWidget
{
	Q_OBJECT

public:
	CometMainWindow(QWidget *parent = nullptr);
	~CometMainWindow();

protected:
	virtual void resizeEvent(QResizeEvent *event) override;
	virtual void changeEvent(QEvent *event) override;

private slots:
	void onPreviewContextMenuRequested();
	void onPreviewResized();

private:
	void initUI();
	void createMainContent();
	static void RenderPreview(void *data, uint32_t cx, uint32_t cy);

private:
	// 顶部栏
	TopBar *m_topBar;

	// 主内容
	QWidget *m_mainContent;

	// 场景面板
	ScenePanel *m_scenePanel;
	// 互动玩法面板
	InteractPanel *m_interactPanel;

	// 预览头部
	PreviewHeader *m_previewHeader;
	// 预览控件
	OBSBasicPreview *m_previewWidget;
	// 混音器面板
	AudioMixPanel *m_audioMixPanel;
};