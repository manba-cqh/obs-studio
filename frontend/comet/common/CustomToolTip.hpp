#pragma once

#include <QLabel>
#include <QPixmap>
#include <QWidget>

class CustomToolTip : public QWidget
{
	Q_OBJECT

public:
	explicit CustomToolTip(const QString &text, QWidget *parent = nullptr);

	void setText(const QString &text);

protected:
	void paintEvent(QPaintEvent *) override;

private:
	QLabel *m_label;
	QPixmap m_bgPixmap;
};
