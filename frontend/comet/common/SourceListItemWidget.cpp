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

SourceListItemWidget::SourceListItemWidget(const QString &text, OBSSceneItem sceneitem, const char *sourceId, QWidget *parent)
    : QWidget(parent), 
    m_text(text),
	m_sceneitem(sceneitem),
	m_sourceId(sourceId)
{
    initUI();
	updateButtonStates();
}

SourceListItemWidget::~SourceListItemWidget()
{
}

void SourceListItemWidget::initUI()
{
    setAttribute(Qt::WA_StyledBackground, true);

    m_layout = new QHBoxLayout(this);
    m_layout->setContentsMargins(5, 5, 5, 5);
    m_layout->setSpacing(5);

    m_iconLabel = new QLabel(this);
    m_iconLabel->setFixedSize(24, 24);
    if (m_sourceId) {
        QPixmap pixmap(QString(":/images/%1.svg").arg(m_sourceId));
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
    m_lockButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("display_lock.png", "display_lock_hover.png", "display_lock_hover.png", "display_unlock.png", "display_unlock_hover.png", "display_unlock_hover.png"));
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
	
	QAction *createGroupAction = m_contextMenu->addAction("创建分组");
	// 添加箭头图标（如果有的话）
	connect(createGroupAction, &QAction::triggered, this, &SourceListItemWidget::onCreateGroupAction);
	
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
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	// 先选择当前源项，然后调用编辑名称
	// 注意：需要确保源项在源树中被选中
	main->EditSceneItemName();
}

void SourceListItemWidget::onCreateGroupAction()
{
	if (!m_sceneitem) {
		return;
	}
	
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	// 创建分组（将当前源项放入分组）
	// 注意：需要先选择源项，然后调用分组功能
	// 这里暂时使用 OBS 的源树分组功能
	// 如果 SourceTree 有 GroupSelectedItems 方法，可以通过 ui->sources 调用
	// 暂时先注释，需要根据实际 UI 结构实现
	// main->ui->sources->GroupSelectedItems();
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
