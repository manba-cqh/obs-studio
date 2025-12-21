#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <obs.hpp>

class SourceListItemWidget : public QWidget
{
	Q_OBJECT

public:
	explicit SourceListItemWidget(const QString &text, OBSSceneItem sceneitem, const char *sourceId = nullptr, QWidget *parent = nullptr);
    ~SourceListItemWidget();

    void setText(const QString &text);
    QString text() const;
	void updateButtonStates();

private:
    void initUI();
	void onHideButtonClicked();
	void onLockButtonClicked();

private:
    QHBoxLayout *m_layout;

    QLabel *m_iconLabel;
    QLabel *m_textLabel;
	QPushButton *m_hideButton;
	QPushButton *m_lockButton;
	QPushButton *m_moreButton;
	
	QString m_text;
	OBSSceneItem m_sceneitem;
	const char *m_sourceId;
};