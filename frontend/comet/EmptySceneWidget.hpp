#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

class EmptySceneWidget : public QWidget
{
	Q_OBJECT

public:
	EmptySceneWidget(QWidget *parent = nullptr);
	~EmptySceneWidget();

signals:
	void sourceTypeSelected(const QString &sourceType);

private:
	void initUI();
	void createSourceButton(const QString &iconPath, const QString &text, const QString &sourceType);

private:
	QVBoxLayout *m_mainLayout;
	QLabel *m_titleLabel;
	QWidget *m_buttonsContainer;
	QHBoxLayout *m_buttonsLayout;
};

