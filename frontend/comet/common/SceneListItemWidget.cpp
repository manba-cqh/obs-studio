#include "SceneListItemWidget.hpp"
#include <QPushButton>
#include <QVBoxLayout>
#include <QIcon>
#include <QPixmap>
#include <QMenu>
#include <QAction>
#include <QPoint>
#include <QMessageBox>
#include <QMouseEvent>
#include <QEnterEvent>
#include <QFontMetrics>
#include <QResizeEvent>
#include <QSizePolicy>
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
	if (m_contextMenu) {
		delete m_contextMenu;
		m_contextMenu = nullptr;
	}
}

void SceneListItemWidget::initUI()
{
	setAttribute(Qt::WA_StyledBackground, true);
	setAttribute(Qt::WA_AcceptTouchEvents, true);
	setProperty("scene_item", true);
	setCursor(Qt::PointingHandCursor);
	setMouseTracking(true);
	setFocusPolicy(Qt::StrongFocus);

	m_layout = new QHBoxLayout(this);
	m_layout->setContentsMargins(8, 0, 4, 0);
	m_layout->setSpacing(4);

	m_textLabel = new QLabel(this);
	m_textLabel->setText(m_text);
	m_textLabel->setStyleSheet("font-size: 14px; font-weight: medium; color: rgba(238, 239, 255, 1);");
	m_textLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
	m_textLabel->setMinimumWidth(0);
	updateElidedText();
	
	m_layout->addWidget(m_textLabel);

	m_layout->addStretch();

	m_moreButton = new QPushButton(this);
	m_moreButton->setFixedSize(24, 24);
	m_moreButton->setCursor(Qt::PointingHandCursor);
	m_moreButton->setStyleSheet(BUTTON_QSS_STYLE("display_more.png", "display_more_hover.png", "display_more_hover.png"));
	connect(m_moreButton, &QPushButton::clicked, this, &SceneListItemWidget::onMoreButtonClicked);
	QWidget *btnContainer = new QWidget(this);
	QVBoxLayout *btnLayout = new QVBoxLayout(btnContainer);
	btnLayout->setContentsMargins(0, 0, 0, 0);
	btnLayout->addStretch();
	btnLayout->addWidget(m_moreButton);
	btnLayout->addStretch();
	m_layout->addWidget(btnContainer);
	m_layout->addStretch();
	
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
		updateElidedText();
	}
}

QString SceneListItemWidget::text() const
{
	return m_text;
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
	// 正确判断是否点击在三个点按钮上（使用 mapFrom 转换坐标系）
	if (m_moreButton) {
		QPoint posInBtn = m_moreButton->mapFrom(this, event->pos());
		if (m_moreButton->rect().contains(posInBtn)) {
			QWidget::mousePressEvent(event);
			return;
		}
	}
	
	// 点击场景项主体区域，立即触发选择
	if (event->button() == Qt::LeftButton && m_source) {
		event->accept();
		emit sceneSelected(m_source);
		return;
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

void SceneListItemWidget::resizeEvent(QResizeEvent *event)
{
	QWidget::resizeEvent(event);
	updateElidedText();
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
				updateElidedText();
			}
		}
	}
}

void SceneListItemWidget::updateElidedText()
{
	if (!m_textLabel)
		return;
	QFontMetrics fm(m_textLabel->font());
	int available = m_textLabel->width();
	if (available > 0) {
		QString elided = fm.elidedText(m_text, Qt::ElideRight, available);
		m_textLabel->setText(elided);
		m_textLabel->setToolTip(m_text);
	} else {
		m_textLabel->setText(m_text);
		m_textLabel->setToolTip(QString());
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
	m_contextMenu = new QMenu();
	
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
	
	OBSScene scene = obs_scene_from_source(m_source);
	if (!scene) {
		return;
	}

	obs_frontend_set_current_scene(m_source);
	/* 使用 OBS 标准确认框，与主界面删除场景一致 */
	if (!main->QueryRemoveSource(m_source)) {
		return;
	}
	main->RemoveSelectedScene(true);
	emit sceneChanged();
}
