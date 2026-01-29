#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QResizeEvent>
#include <obs.hpp>
#include <obs-frontend-api.h>
#include <widgets/OBSQTDisplay.hpp>

#include "CommonComboBox.hpp"

class DirectorWidget : public QWidget
{
	Q_OBJECT

public:
	DirectorWidget(QWidget *parent = nullptr);
	~DirectorWidget();

protected:
	virtual void resizeEvent(QResizeEvent *event) override;

private slots:
	void onSyncToProgramClicked();
	void onEnlargeProgramClicked();
	void onTransitionChanged(int index);
	void syncPreviewToProgram();

private:
	void initUI();
	void setupPreviewDisplay();
	void setupProgramDisplay();
	static void RenderPreview(void *data, uint32_t cx, uint32_t cy);
	static void RenderProgram(void *data, uint32_t cx, uint32_t cy);

private:
	// 预览画面
	QLabel *m_previewLabel;
	OBSQTDisplay *m_previewDisplay;
	
	// 直播画面
	QLabel *m_programLabel;
	OBSQTDisplay *m_programDisplay1;
	
	// 转场选项
	QLabel *m_transitionLabel;
	CommonComboBox *m_transitionCombo;
	
	// 操作按钮
	QPushButton *m_syncButton;
	QPushButton *m_enlargeButton;
	
	// 布局
	QVBoxLayout *m_mainLayout;
	QHBoxLayout *m_contentLayout;
	QVBoxLayout *m_previewLayout;
	QVBoxLayout *m_programLayout;
	QHBoxLayout *m_controlLayout;
	
	// 预览缩放参数
	float m_previewScale;
	int m_previewX;
	int m_previewY;
	int m_previewCX;
	int m_previewCY;
};

