#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMenu>
#include <obs.hpp>

class SourceListItemWidget : public QWidget
{
	Q_OBJECT

signals:
	void sourcesChanged();

public:
	explicit SourceListItemWidget(const QString &text, OBSSceneItem sceneitem, const char *sourceId = nullptr, QWidget *parent = nullptr, bool isGroup = false, bool indented = false);
    ~SourceListItemWidget();

    void setText(const QString &text);
    QString text() const;
	OBSSceneItem getSceneItem() const { return m_sceneitem; }
	void updateButtonStates();
	void addMoveToGroupAction(const QString &groupName);

private:
	void initUI(bool isGroup = false, bool indented = false);
	void onHideButtonClicked();
	void onLockButtonClicked();
	void onMoreButtonClicked();
	void createContextMenu();
	void populateMoveToGroupMenu();
	
	// 菜单项槽函数
	void onEditAction();
	void onFilterAction();
	void onMaskAction();
	void onRenameAction();
	void onMoveToGroup(const QString &groupName);
	void onMoveToNewGroup();
	void onDeleteAction();

private:
    QHBoxLayout *m_layout;

    QLabel *m_iconLabel;
    QLabel *m_textLabel;
	QPushButton *m_hideButton;
	QPushButton *m_lockButton;
	QPushButton *m_moreButton;
	QMenu *m_contextMenu;
	QMenu *m_moveToGroupMenu;
	
	QString m_text;
	OBSSceneItem m_sceneitem;
	const char *m_sourceId;
};