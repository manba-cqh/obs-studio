#pragma once

#include <QVBoxLayout>
#include <QWidget>

class TopBar;
class ScenePanel;

class CometMainWindow : public QWidget
{
	Q_OBJECT

public:
	CometMainWindow(QWidget *parent = nullptr);
	~CometMainWindow();

private:
	void initUI();
	void createMainContent();

private:
	// 顶部栏
	TopBar *m_topBar;

	// 主内容
	QWidget *m_mainContent;

	// 场景面板
	ScenePanel *m_scenePanel;
};