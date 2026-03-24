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
	void setCollapsed(bool collapsed);
	bool isCollapsed() const { return m_collapsed; }

	void resetContentMargins(int left, int top, int right, int bottom);

protected:
	virtual void paintEvent(QPaintEvent *event) override;

private:
	void initUI();

private:
	// 主布局
	QVBoxLayout *m_mainLayout;

	// 主内容区域
	QWidget *m_contentWidget;
	
	// 分隔线
	QWidget *m_separator;
	
	// 是否折叠
	bool m_collapsed;
};

