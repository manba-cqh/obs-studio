#include <QPushButton>
#include <QIcon>
#include <QPixmap>
#include <cstring>

#include "tools.hpp"
#include "SourceListItemWidget.hpp"
#include <widgets/OBSBasic.hpp>
#include <obs-frontend-api.h>

SourceListItemWidget::SourceListItemWidget(const QString &text, OBSSceneItem sceneitem, const char *sourceId, QWidget *parent)
    : QWidget(parent), 
    m_text(text),
	m_sceneitem(sceneitem),
	m_sourceId(sourceId),
	m_hideButton(nullptr),
	m_lockButton(nullptr),
	m_moreButton(nullptr)
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

    m_hideButton = new QPushButton(this);
    m_hideButton->setFixedSize(24, 24);
    m_hideButton->setCheckable(true);
    connect(m_hideButton, &QPushButton::clicked, this, &SourceListItemWidget::onHideButtonClicked);
    m_layout->addWidget(m_hideButton);

    m_lockButton = new QPushButton(this);
    m_lockButton->setFixedSize(24, 24);
    m_lockButton->setCheckable(true);
    connect(m_lockButton, &QPushButton::clicked, this, &SourceListItemWidget::onLockButtonClicked);
    m_layout->addWidget(m_lockButton);

    m_moreButton = new QPushButton(this);
    m_moreButton->setFixedSize(24, 24);
    m_moreButton->setIcon(QIcon(":/images/move_up.png"));
    m_layout->addWidget(m_moreButton);
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
		// 按钮的样式可以通过 CSS 根据 checked 状态来改变外观
	}
	
	// 更新锁定按钮状态
	if (m_lockButton) {
		bool locked = obs_sceneitem_locked(m_sceneitem);
		m_lockButton->setChecked(locked);
		// 按钮的样式可以通过 CSS 根据 checked 状态来改变外观
	}
}
