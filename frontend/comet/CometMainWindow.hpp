#pragma once

#include <QVBoxLayout>
#include <QWidget>

#include <widgets/OBSQTDisplay.hpp>

class TopBar;
class ScenePanel;
class InteractPanel;

class CometMainWindow : public QWidget
{
	Q_OBJECT

public:
	CometMainWindow(QWidget *parent = nullptr);
	~CometMainWindow();

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

	// 预览控件
	OBSQTDisplay *m_previewWidget;
};