#include <QPushButton>
#include <QIcon>
#include <QPixmap>
#include <QMenu>
#include <QAction>
#include <QPoint>
#include <cstring>

#include "tools.hpp"
#include "SourceListItemWidget.hpp"
#include "CenterToolTipButton.hpp"
#include <widgets/OBSBasic.hpp>
#include <obs-frontend-api.h>
#include <obs-source.h>
#include <dialogs/NameDialog.hpp>
#include <qt-wrappers.hpp>
#include <QMessageBox>

SourceListItemWidget::SourceListItemWidget(const QString &text, OBSSceneItem sceneitem, const char *sourceId, QWidget *parent, bool isGroup, bool indented)
    : QWidget(parent), 
    m_text(text),
	m_sceneitem(sceneitem),
	m_sourceId(sourceId)
{
    initUI(isGroup, indented);
	updateButtonStates();
}

SourceListItemWidget::~SourceListItemWidget()
{
}

void SourceListItemWidget::initUI(bool isGroup, bool indented)
{
    setAttribute(Qt::WA_StyledBackground, true);

    m_layout = new QHBoxLayout(this);
    int leftMargin = indented ? 28 : 5;
    m_layout->setContentsMargins(leftMargin, 5, 5, 5);
    m_layout->setSpacing(5);

    m_iconLabel = new QLabel(this);
    m_iconLabel->setFixedSize(24, 24);
    QString iconPath;
    if (isGroup) {
        iconPath = QStringLiteral(":/images/folder_open.svg");
    } else if (m_sourceId) {
        iconPath = QString(":/images/%1.svg").arg(m_sourceId);
    }
    if (!iconPath.isEmpty()) {
        QPixmap pixmap(iconPath);
        if (!pixmap.isNull()) {
            m_iconLabel->setPixmap(pixmap.scaled(24, 24, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        }
    }
    m_layout->addWidget(m_iconLabel);

    m_textLabel = new QLabel(this);
    m_textLabel->setText(m_text);
    m_textLabel->setStyleSheet("font-size: 12px; font-weight: medium; color: rgba(238, 239, 255, 1);");
    m_layout->addWidget(m_textLabel);

    m_layout->addStretch();

    m_hideButton = new CenterToolTipButton(this);
    m_hideButton->setFixedSize(24, 24);
    m_hideButton->setCheckable(true);
    m_hideButton->setChecked(false);
    m_hideButton->setToolTip("隐藏/显示");
    m_hideButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("display.png", "display_hover.png", "display_hover.png", "hide.png", "hide_hover.png", "hide_hover.png"));
    connect(m_hideButton, &QPushButton::clicked, this, &SourceListItemWidget::onHideButtonClicked);
    m_layout->addWidget(m_hideButton);

    m_lockButton = new CenterToolTipButton(this);
    m_lockButton->setFixedSize(24, 24);
    m_lockButton->setCheckable(true);
    m_lockButton->setChecked(false);
    m_lockButton->setToolTip("锁定/解锁");
    m_lockButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("display_unlock.png", "display_unlock_hover.png", "display_unlock_hover.png", "display_lock.png", "display_lock_hover.png", "display_lock_hover.png"));
    connect(m_lockButton, &QPushButton::clicked, this, &SourceListItemWidget::onLockButtonClicked);
    m_layout->addWidget(m_lockButton);

    m_moreButton = new CenterToolTipButton(this);
    m_moreButton->setFixedSize(24, 24);
    m_moreButton->setToolTip("更多操作");
    m_moreButton->setStyleSheet(BUTTON_QSS_STYLE("display_more.png", "display_more_hover.png", "display_more_hover.png"));
    connect(m_moreButton, &QPushButton::clicked, this, &SourceListItemWidget::onMoreButtonClicked);
    m_layout->addWidget(m_moreButton);
    
    // 创建上下文菜单
    createContextMenu();
}

void SourceListItemWidget::setText(const QString &text)
{
    m_textLabel->setText(text);
}

QString SourceListItemWidget::text() const
{
    return m_textLabel ? m_textLabel->text() : QString();
}

void SourceListItemWidget::onHideButtonClicked()
{
	if (!m_sceneitem) {
		return;
	}
	
	bool visible = obs_sceneitem_visible(m_sceneitem);
	obs_sceneitem_set_visible(m_sceneitem, !visible);
	updateButtonStates();
}

void SourceListItemWidget::onLockButtonClicked()
{
	if (!m_sceneitem) {
		return;
	}
	
	bool locked = obs_sceneitem_locked(m_sceneitem);
	obs_sceneitem_set_locked(m_sceneitem, !locked);
	updateButtonStates();
}

void SourceListItemWidget::updateButtonStates()
{
	if (!m_sceneitem) {
		return;
	}
	
	// 更新隐藏按钮状态
	if (m_hideButton) {
		bool visible = obs_sceneitem_visible(m_sceneitem);
		m_hideButton->setChecked(!visible);  // 隐藏时按钮为选中状态
		// 根据状态更新 tooltip
		m_hideButton->setToolTip(visible ? "隐藏" : "显示");
	}
	
	// 更新锁定按钮状态
	if (m_lockButton) {
		bool locked = obs_sceneitem_locked(m_sceneitem);
		m_lockButton->setChecked(locked);
		// 根据状态更新 tooltip
		m_lockButton->setToolTip(locked ? "解锁" : "锁定");
	}
}

void SourceListItemWidget::onMoreButtonClicked()
{
	if (!m_contextMenu) {
		return;
	}
	
	// 在按钮下方显示菜单
	QPoint pos = m_moreButton->mapToGlobal(QPoint(0, m_moreButton->height()));
	m_contextMenu->exec(pos);
}

void SourceListItemWidget::createContextMenu()
{
	m_contextMenu = new QMenu(this);
    m_contextMenu->setFixedSize(114, 242);
	
	QAction *editAction = m_contextMenu->addAction("编辑");
	connect(editAction, &QAction::triggered, this, &SourceListItemWidget::onEditAction);
	
	QAction *filterAction = m_contextMenu->addAction("滤镜");
	connect(filterAction, &QAction::triggered, this, &SourceListItemWidget::onFilterAction);
	
	QAction *maskAction = m_contextMenu->addAction("蒙版");
	connect(maskAction, &QAction::triggered, this, &SourceListItemWidget::onMaskAction);
	
	QAction *renameAction = m_contextMenu->addAction("重命名");
	connect(renameAction, &QAction::triggered, this, &SourceListItemWidget::onRenameAction);
	
	m_contextMenu->addSeparator();
	
	m_moveToGroupMenu = new QMenu("移至分组", this);
	connect(m_moveToGroupMenu, &QMenu::aboutToShow, this, &SourceListItemWidget::populateMoveToGroupMenu);
	m_contextMenu->addMenu(m_moveToGroupMenu);
	
	m_contextMenu->addSeparator();
	
	QAction *deleteAction = m_contextMenu->addAction("删除素材");
	deleteAction->setProperty("delete_action", true); // 标记为删除操作
	connect(deleteAction, &QAction::triggered, this, &SourceListItemWidget::onDeleteAction);
}

void SourceListItemWidget::onEditAction()
{
	if (!m_sceneitem) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	OBSSource source = obs_sceneitem_get_source(m_sceneitem);
	if (!source) {
		return;
	}
	
	// 打开源属性窗口
	main->CreatePropertiesWindow(source);
}

void SourceListItemWidget::onFilterAction()
{
	if (!m_sceneitem) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	OBSSource source = obs_sceneitem_get_source(m_sceneitem);
	if (!source) {
		return;
	}
	
	// 打开滤镜窗口
	main->CreateFiltersWindow(source);
}

void SourceListItemWidget::onMaskAction()
{
	if (!m_sceneitem) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	OBSSource source = obs_sceneitem_get_source(m_sceneitem);
	if (!source) {
		return;
	}
	
	// 打开交互式蒙版编辑（使用 OBS 的交互窗口）
	// 注意：OBS 可能没有直接的 CreateInteractWindow，这里先打开属性窗口
	// 如果需要专门的蒙版编辑，可能需要调用其他方法
	main->CreatePropertiesWindow(source);
}

void SourceListItemWidget::onRenameAction()
{
	if (!m_sceneitem) {
		return;
	}
	OBSSource source = obs_sceneitem_get_source(m_sceneitem);
	if (!source) {
		return;
	}
	const char *prevName = obs_source_get_name(source);
	if (!prevName) {
		return;
	}
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
		obs_source_set_name(source, name.c_str());
		m_text = QString::fromUtf8(name.c_str());
		setText(m_text);
		emit sourcesChanged();
		break;
	}
}

namespace {

struct EnumGroupsData {
	SourceListItemWidget *widget;
	const char *currentGroupName;
};

static bool enumGroupsCallback(obs_scene_t *, obs_sceneitem_t *item, void *param)
{
	EnumGroupsData *data = static_cast<EnumGroupsData *>(param);
	if (!obs_sceneitem_is_group(item)) {
		return true;
	}
	obs_source_t *src = obs_sceneitem_get_source(item);
	if (!src) {
		return true;
	}
	const char *name = obs_source_get_name(src);
	if (!name || (data->currentGroupName && strcmp(name, data->currentGroupName) == 0)) {
		return true; // 跳过当前项所在的分组
	}
	data->widget->addMoveToGroupAction(QString::fromUtf8(name));
	return true;
}

} // namespace

void SourceListItemWidget::populateMoveToGroupMenu()
{
	m_moveToGroupMenu->clear();
	
	if (!m_sceneitem) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	OBSScene scene = main->GetCurrentScene();
	if (!scene) {
		return;
	}
	
	obs_scene_t *enumScene = obs_scene_from_source(obs_scene_get_source(scene));
	obs_sceneitem_t *currentGroup = obs_sceneitem_get_group(enumScene, m_sceneitem);
	const char *currentGroupName = currentGroup ? obs_source_get_name(obs_sceneitem_get_source(currentGroup)) : nullptr;
	
	EnumGroupsData data = {this, currentGroupName};
	obs_scene_enum_items(enumScene, enumGroupsCallback, &data);
	
	if (m_moveToGroupMenu->isEmpty()) {
		QAction *none = m_moveToGroupMenu->addAction("(无分组)");
		none->setEnabled(false);
	}
}

void SourceListItemWidget::addMoveToGroupAction(const QString &groupName)
{
	QAction *action = m_moveToGroupMenu->addAction(groupName);
	connect(action, &QAction::triggered, this, [this, groupName]() {
		onMoveToGroup(groupName);
	});
}

void SourceListItemWidget::onMoveToGroup(const QString &groupName)
{
	if (!m_sceneitem || groupName.isEmpty()) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	OBSScene scene = main->GetCurrentScene();
	if (!scene) {
		return;
	}
	
	obs_scene_t *rootScene = obs_scene_from_source(obs_scene_get_source(scene));
	obs_sceneitem_t *currentGroup = obs_sceneitem_get_group(rootScene, m_sceneitem);
	// 若当前已在某分组内，先移出再加入目标分组
	if (currentGroup) {
		obs_sceneitem_group_remove_item(currentGroup, m_sceneitem);
	}
	
	obs_sceneitem_t *groupItem = obs_scene_get_group(scene, groupName.toUtf8().constData());
	if (!groupItem) {
		return;
	}
	
	obs_sceneitem_group_add_item(groupItem, m_sceneitem);
	emit sourcesChanged();
}

void SourceListItemWidget::onDeleteAction()
{
	if (!m_sceneitem) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	// 删除源项
	OBSScene scene = obs_sceneitem_get_scene(m_sceneitem);
	if (!scene) {
		return;
	}
	
	obs_sceneitem_remove(m_sceneitem);
	
	// 通知场景面板更新
	emit sourcesChanged();
}
