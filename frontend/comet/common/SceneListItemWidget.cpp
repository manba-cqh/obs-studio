#include "SceneListItemWidget.hpp"
#include <QPushButton>
#include <QIcon>
#include <QPixmap>
#include <QMenu>
#include <QAction>
#include <QPoint>
#include <QMessageBox>
#include <QMouseEvent>
#include <QEnterEvent>
#include <cstring>

#include "tools/tools.hpp"
#include <widgets/OBSBasic.hpp>
#include <obs-frontend-api.h>
#include <obs-source.h>
#include <dialogs/NameDialog.hpp>
#include <qt-wrappers.hpp>
#include <string>

SceneListItemWidget::SceneListItemWidget(OBSSource source, QWidget *parent)
	: QWidget(parent)
	, m_source(source)
	, m_checked(false)
{
	if (m_source) {
		const char *sceneName = obs_source_get_name(m_source);
		if (sceneName) {
			m_text = QString::fromUtf8(sceneName);
		}
	}
	initUI();
}

SceneListItemWidget::~SceneListItemWidget()
{
}

void SceneListItemWidget::initUI()
{
	setAttribute(Qt::WA_StyledBackground, true);
	setProperty("scene_item", true);
	setCursor(Qt::PointingHandCursor);
	setMouseTracking(true); // 启用鼠标跟踪以支持悬停效果

	m_layout = new QHBoxLayout(this);
	m_layout->setContentsMargins(12, 8, 8, 8);
	m_layout->setSpacing(8);

	m_textLabel = new QLabel(this);
	m_textLabel->setText(m_text);
	m_textLabel->setStyleSheet("font-size: 14px; font-weight: medium; color: rgba(238, 239, 255, 1);");
	m_layout->addWidget(m_textLabel);

	m_layout->addStretch();

	m_moreButton = new QPushButton(this);
	m_moreButton->setFixedSize(24, 24);
	m_moreButton->setCursor(Qt::PointingHandCursor);
	m_moreButton->setStyleSheet(BUTTON_QSS_STYLE("display_more.png", "display_more_hover.png", "display_more_hover.png"));
	connect(m_moreButton, &QPushButton::clicked, this, &SceneListItemWidget::onMoreButtonClicked);
	m_layout->addWidget(m_moreButton);
	
	// 为三个点按钮安装事件过滤器，防止点击事件冒泡
	m_moreButton->installEventFilter(this);
	
	// 创建上下文菜单
	createContextMenu();
	
	// 设置初始样式
	setChecked(false);
}

void SceneListItemWidget::setText(const QString &text)
{
	m_text = text;
	if (m_textLabel) {
		m_textLabel->setText(text);
	}
}

QString SceneListItemWidget::text() const
{
	return m_textLabel ? m_textLabel->text() : QString();
}

void SceneListItemWidget::setChecked(bool checked)
{
	m_checked = checked;
	// 更新样式以反映选中状态
	if (checked) {
		setStyleSheet(
			"QWidget[scene_item=true] {"
			"    background: rgba(62, 62, 82, 1);"
			"    border-radius: 4px;"
			"}"
		);
	} else {
		setStyleSheet(
			"QWidget[scene_item=true] {"
			"    background: transparent;"
			"    border-radius: 4px;"
			"}"
		);
	}
}

bool SceneListItemWidget::eventFilter(QObject *obj, QEvent *event)
{
	// 如果事件来自三个点按钮，不处理（让它正常响应点击）
	if (obj == m_moreButton) {
		return QWidget::eventFilter(obj, event);
	}
	return QWidget::eventFilter(obj, event);
}

void SceneListItemWidget::mousePressEvent(QMouseEvent *event)
{
	// 如果点击的是三个点按钮区域，不触发场景选择
	if (m_moreButton && m_moreButton->geometry().contains(event->pos())) {
		QWidget::mousePressEvent(event);
		return;
	}
	
	// 点击场景项，触发选择
	if (event->button() == Qt::LeftButton && m_source) {
		emit sceneSelected(m_source);
	}
	
	QWidget::mousePressEvent(event);
}

void SceneListItemWidget::enterEvent(QEnterEvent *event)
{
	// 悬停效果 - 仅在未选中时显示
	if (!m_checked) {
		setStyleSheet(
			"QWidget[scene_item=true] {"
			"    background: rgba(124, 124, 164, 0.3);"
			"    border-radius: 4px;"
			"}"
		);
	}
	QWidget::enterEvent(event);
}

void SceneListItemWidget::leaveEvent(QEvent *event)
{
	// 恢复原始样式
	setChecked(m_checked);
	QWidget::leaveEvent(event);
}

bool SceneListItemWidget::isChecked() const
{
	return m_checked;
}

void SceneListItemWidget::updateSceneName()
{
	if (m_source) {
		const char *sceneName = obs_source_get_name(m_source);
		if (sceneName) {
			m_text = QString::fromUtf8(sceneName);
			if (m_textLabel) {
				m_textLabel->setText(m_text);
			}
		}
	}
}

void SceneListItemWidget::onMoreButtonClicked()
{
	if (!m_contextMenu) {
		return;
	}
	
	// 在按钮下方显示菜单
	QPoint pos = m_moreButton->mapToGlobal(QPoint(0, m_moreButton->height()));
	m_contextMenu->exec(pos);
}

void SceneListItemWidget::createContextMenu()
{
	m_contextMenu = new QMenu(this);
	
	QAction *renameAction = m_contextMenu->addAction("重命名");
	connect(renameAction, &QAction::triggered, this, &SceneListItemWidget::onRenameAction);
	
	m_contextMenu->addSeparator();
	
	QAction *deleteAction = m_contextMenu->addAction("删除场景");
	deleteAction->setProperty("delete_action", true);
	connect(deleteAction, &QAction::triggered, this, &SceneListItemWidget::onDeleteAction);
}

void SceneListItemWidget::onRenameAction()
{
	if (!m_source) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	const char *prevName = obs_source_get_name(m_source);
	if (!prevName) {
		return;
	}
	
	// 使用 NameDialog 获取新名称
	for (;;) {
		std::string name;
		bool accepted = NameDialog::AskForName(this, QTStr("Basic.Main.MixerRename.Title"),
						       QTStr("Basic.Main.MixerRename.Text"), name, QT_UTF8(prevName));
		if (!accepted) {
			return;
		}
		
		if (name.empty()) {
			QMessageBox::warning(this, QTStr("NoNameEntered.Title"), QTStr("NoNameEntered.Text"));
			continue;
		}
		
		OBSSourceAutoRelease sourceTest = obs_get_source_by_name(name.c_str());
		
		if (sourceTest) {
			QMessageBox::warning(this, QTStr("NameExists.Title"), QTStr("NameExists.Text"));
			continue;
		}
		
		// 重命名场景源
		obs_source_set_name(m_source, name.c_str());
		
		// 更新显示
		updateSceneName();
		
		// 通知场景列表变化（OBS 会自动触发事件，这里通过信号通知父组件）
		emit sceneChanged();
		
		break;
	}
}

void SceneListItemWidget::onDeleteAction()
{
	if (!m_source) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	// 确认删除
	const char *sceneName = obs_source_get_name(m_source);
	QString message = QString("确定要删除场景 '%1' 吗？").arg(QString::fromUtf8(sceneName));
	
	QMessageBox::StandardButton reply = QMessageBox::question(this, "删除场景", message,
								  QMessageBox::Yes | QMessageBox::No);
	if (reply != QMessageBox::Yes) {
		return;
	}
	
	// 设置当前场景为要删除的场景（如果还没有设置）
	OBSScene scene = obs_scene_from_source(m_source);
	if (scene) {
		// 先切换到要删除的场景
		obs_frontend_set_current_scene(m_source);
		
		// 已在本处确认过，跳过 RemoveSelectedScene 内部的二次确认
		main->RemoveSelectedScene(true);
		
		// 通知场景列表变化
		emit sceneChanged();
	}
}
