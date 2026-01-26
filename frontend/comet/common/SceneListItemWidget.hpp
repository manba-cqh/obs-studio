#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMenu>
#include <obs.hpp>

class SceneListItemWidget : public QWidget
{
	Q_OBJECT

signals:
	void sceneChanged();
	void sceneSelected(OBSSource source);

public:
	explicit SceneListItemWidget(OBSSource source, QWidget *parent = nullptr);
	~SceneListItemWidget();

	void setText(const QString &text);
	QString text() const;
	void setChecked(bool checked);
	bool isChecked() const;
	void updateSceneName();

protected:
	bool eventFilter(QObject *obj, QEvent *event) override;
	void mousePressEvent(QMouseEvent *event) override;
	void enterEvent(QEnterEvent *event) override;
	void leaveEvent(QEvent *event) override;

private:
	void initUI();
	void onMoreButtonClicked();
	void createContextMenu();
	
	// 菜单项槽函数
	void onRenameAction();
	void onDeleteAction();

private:
	QHBoxLayout *m_layout;

	QLabel *m_textLabel;
	QPushButton *m_moreButton;
	QMenu *m_contextMenu;
	
	OBSSource m_source;
	QString m_text;
	bool m_checked;
};
