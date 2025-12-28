#pragma once

#include <QWidget>
#include <QVBoxLayout>

class PanelContainer : public QWidget
{
	Q_OBJECT
public:
	explicit PanelContainer(QWidget *parent = nullptr);
	virtual ~PanelContainer();

	void setContentWidget(QWidget *widget);

protected:
	virtual void paintEvent(QPaintEvent *event) override;

private:
	void initUI();

private:
	// 主布局
	QVBoxLayout *m_mainLayout;

	// 主内容区域
	QWidget *m_contentWidget;
};

