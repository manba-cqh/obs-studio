#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>

class SourceListItemWidget : public QWidget
{
	Q_OBJECT

public:
	explicit SourceListItemWidget(const QString &text, QWidget *parent = nullptr);
    ~SourceListItemWidget();

    void setText(const QString &text);
    QString text() const;

private:
    void initUI();

private:
    QHBoxLayout *m_layout;

    QLabel *m_textLabel;
	QString m_text;
};