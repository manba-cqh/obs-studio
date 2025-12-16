#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

class PanelContainer : public QWidget
{
	Q_OBJECT

public:
	explicit PanelContainer(const QString &title, QWidget *parent = nullptr);
	virtual ~PanelContainer();

	void setHeaderOperWidget(QWidget *widget);
	void setContentWidget(QWidget *widget);

	void setTitle(const QString &title);
	QString title() const;

	void setCollapsed(bool collapsed);
	bool isCollapsed() const;
protected:
	virtual void paintEvent(QPaintEvent *event) override;

private slots:
	void onCollapseButtonClicked();
	void onFloatingButtonClicked();

private:
	void initUI();
	void createHeader();

private:
	// 主布局
	QVBoxLayout *m_mainLayout;

	// 头部
	QHBoxLayout *m_headerLayout;
	QPushButton *m_collapseButton;

	// 主内容区域
	QWidget *m_contentWidget;

	// 状态
	bool m_collapsed;
	QString m_title;
};

