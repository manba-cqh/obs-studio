#include <QPushButton>

#include "SourceListItemWidget.hpp"

SourceListItemWidget::SourceListItemWidget(const QString &text, QWidget *parent)
    : QWidget(parent), 
    m_text(text)
{
    initUI();
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

    QLabel *iconLabel = new QLabel(this);
    iconLabel->setFixedSize(24, 24);
    m_layout->addWidget(iconLabel);

    m_textLabel = new QLabel(this);
    m_textLabel->setText(m_text);
    m_textLabel->setStyleSheet("font-size: 12px; font-weight: medium; color: rgba(238, 239, 255, 1);");
    m_layout->addWidget(m_textLabel);

    m_layout->addStretch();

    QPushButton *hideButton = new QPushButton(this);
    hideButton->setFixedSize(24, 24);
    hideButton->setIcon(QIcon(":/images/hide.png"));
    m_layout->addWidget(hideButton);

    QPushButton *lockButton = new QPushButton(this);
    lockButton->setFixedSize(24, 24);
    lockButton->setIcon(QIcon(":/images/lock.png"));
    m_layout->addWidget(lockButton);

    QPushButton *moreButton = new QPushButton(this);
    moreButton->setFixedSize(24, 24);
    moreButton->setIcon(QIcon(":/images/move_up.png"));
    m_layout->addWidget(moreButton);
}

void SourceListItemWidget::setText(const QString &text)
{
    m_textLabel->setText(text);
}

QString SourceListItemWidget::text() const
{
    return m_textLabel ? m_textLabel->text() : QString();
}