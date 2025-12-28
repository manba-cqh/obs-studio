#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

class PanelHeaderWidget : public QWidget
{
	Q_OBJECT

signals:
	void sigFloating(bool floating);
	void sigCollapseClicked();

public:
	explicit PanelHeaderWidget(const QString &title, QWidget *parent = nullptr);
	~PanelHeaderWidget();

	void setTitle(const QString &title);
	QString title() const;

	void setHeaderOperWidget(QWidget *widget);
	void setCollapseButtonChecked(bool checked);

private slots:
	void onCollapseButtonClicked();
	void onFloatingButtonClicked();

private:
	QHBoxLayout *m_headerLayout;
	QPushButton *m_collapseButton;
	QLabel *m_titleLabel;
	QPushButton *m_floatingButton;
	QString m_title;
};

