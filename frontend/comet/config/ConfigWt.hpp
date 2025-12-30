#pragma once

#include <QDialog>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QListWidgetItem>

class AudioConfigWt;

class ConfigWt : public QDialog
{
	Q_OBJECT
public:
	ConfigWt(QWidget *parent = nullptr);
	~ConfigWt();

private:
	void initUI();
	void setupNavigation();
	void switchPage(int index);

private:
	QHBoxLayout *m_mainLayout;
	QListWidget *m_navList;
	QStackedWidget *m_stackedWidget;
	
	AudioConfigWt *m_audioConfig;
};
