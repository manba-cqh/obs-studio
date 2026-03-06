#include "DialogTitleBar.hpp"
#include <QHBoxLayout>
#include <QDialog>

DialogTitleBar::DialogTitleBar(QWidget *targetWindow, QWidget *parent,
                               const QString &title,
                               CornerStyle cornerStyle)
	: MovableWidget(targetWindow, parent)
	, m_titleLabel(nullptr)
	, m_closeButton(nullptr)
{
	setObjectName("DialogTitleBar");
	setFixedHeight(50);
	QString style = "DialogTitleBar { background-color: #2C2C3C; }";
	if (cornerStyle == CornerStyle::TopRounded)
		style += "DialogTitleBar { border-radius: 5px 5px 0 0; }";
	setStyleSheet(style);

	QHBoxLayout *layout = new QHBoxLayout(this);
	layout->setContentsMargins(15, 13, 15, 13);
	layout->setSpacing(0);

	m_titleLabel = new QLabel(title, this);
	m_titleLabel->setTextFormat(Qt::PlainText);
	m_titleLabel->setStyleSheet(
		"QLabel { color: #FFFFFF; font-size: 15px; font-weight: bold; background: transparent; border: none; padding: 0px; }");
	layout->addWidget(m_titleLabel, 0, Qt::AlignVCenter);
	layout->addStretch();

	m_closeButton = new QPushButton(this);
	m_closeButton->setText(QString());  // 无文字，仅显示图标
	m_closeButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	m_closeButton->setFixedSize(24, 24);
	m_closeButton->setCursor(Qt::PointingHandCursor);
	m_closeButton->setStyleSheet(
		"QPushButton { border: none; padding: 0; background: transparent; border-image: url(:/images/close.svg); }"
		"QPushButton:hover { border-image: url(:/images/close_hover.svg); }"
		"QPushButton:pressed { border-image: url(:/images/close_hover.svg); }");
	connect(m_closeButton, &QPushButton::clicked, this, &DialogTitleBar::onCloseClicked);
	layout->addWidget(m_closeButton, 0, Qt::AlignVCenter);
}

void DialogTitleBar::setTitle(const QString &title)
{
	if (m_titleLabel)
		m_titleLabel->setText(title);
}

void DialogTitleBar::onCloseClicked()
{
	if (m_closeCallback) {
		m_closeCallback();
	} else if (QDialog *dlg = qobject_cast<QDialog *>(targetWindow())) {
		dlg->close();
	}
}
