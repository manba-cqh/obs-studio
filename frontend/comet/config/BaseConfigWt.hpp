#pragma once

#include <QWidget>

class BaseConfigWt : public QWidget
{
	Q_OBJECT
public:
	BaseConfigWt(QWidget *parent = nullptr) : QWidget(parent)
	{
		setStyleSheet("QLabel { color: #B4B6D3; font-size: 14px; font-weight: medium; }");
	}
	virtual void saveSettings() {}
};