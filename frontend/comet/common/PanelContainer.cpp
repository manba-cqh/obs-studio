#include <QPainter>
#include <QStyleOption>
#include <QLabel>

#include "tools.hpp"
#include "PanelContainer.hpp"

PanelContainer::PanelContainer(const QString &title, QWidget *parent)
	: QWidget(parent)
	, m_collapsed(false)
	, m_title(title)
{
	initUI();
}

PanelContainer::~PanelContainer()
{
}

void PanelContainer::initUI()
{
	setProperty("pannel_widget", true);

	m_mainLayout = new QVBoxLayout(this);
	m_mainLayout->setContentsMargins(12, 8, 12, 8);
	m_mainLayout->setSpacing(6);

	createHeader();

	QWidget *separator = new QWidget(this);
	separator->setFixedHeight(1);
	separator->setStyleSheet("background-color: rgba(255, 255, 255, 125);");
	m_mainLayout->addWidget(separator);
}

void PanelContainer::createHeader()
{
	QWidget *headerWidget = new QWidget(this);
	headerWidget->setFixedHeight(40);

	m_headerLayout = new QHBoxLayout(headerWidget);
	m_headerLayout->setContentsMargins(0, 0, 0, 0);
	m_headerLayout->setSpacing(0);

	// 折叠按钮
	m_collapseButton = new QPushButton(headerWidget);
	m_collapseButton->setFixedSize(24, 24);
	m_collapseButton->setCheckable(true);
	m_collapseButton->setChecked(false);
	m_collapseButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("drop_down.svg", "drop_down_hover.svg", "drop_down_hover.svg", "drop_down_expanded.png", "drop_down_expanded_hover.png", "drop_down_expanded_hover.png"));
	connect(m_collapseButton, &QPushButton::clicked, this, &PanelContainer::onCollapseButtonClicked);
	m_headerLayout->addWidget(m_collapseButton);
	m_headerLayout->addSpacing(4);

	QLabel *titleLabel = new QLabel(headerWidget);
	titleLabel->setText(m_title);
	titleLabel->setProperty("label_15_medium", true);
	m_headerLayout->addWidget(titleLabel);

	m_headerLayout->addStretch();

	m_headerLayout->addSpacing(8);
	QWidget *separator = new QWidget(headerWidget);
	separator->setFixedSize(1, 10);
	separator->setStyleSheet("background-color: rgba(255, 255, 255, 125);");
	m_headerLayout->addWidget(separator);
	m_headerLayout->addSpacing(8);

	QPushButton *FloatingButton = new QPushButton(headerWidget);
	FloatingButton->setFixedSize(24, 24);
	FloatingButton->setStyleSheet(BUTTON_QSS_STYLE("float.svg", "float_hover.svg", "float_hover.svg"));
	connect(FloatingButton, &QPushButton::clicked, this, &PanelContainer::onFloatingButtonClicked);
	m_headerLayout->addWidget(FloatingButton);

	m_mainLayout->addWidget(headerWidget);
}

void PanelContainer::setHeaderOperWidget(QWidget *widget)
{
	if (m_headerLayout) {
		m_headerLayout->insertWidget(4, widget);
	}
}

void PanelContainer::setContentWidget(QWidget *widget)
{
	m_contentWidget = widget;
	if (m_contentWidget) {
		m_mainLayout->addWidget(m_contentWidget);
		m_mainLayout->addStretch();
	}
}

void PanelContainer::setTitle(const QString &title)
{
	m_title = title;
	if (m_collapseButton) {
		m_collapseButton->setText(title);
	}
}

QString PanelContainer::title() const
{
	return m_title;
}

void PanelContainer::setCollapsed(bool collapsed)
{
	if (m_collapsed == collapsed)
		return;

	m_collapsed = collapsed;

	if (m_contentWidget) {
		m_contentWidget->setVisible(!collapsed);
	}
}

bool PanelContainer::isCollapsed() const
{
	return m_collapsed;
}

void PanelContainer::paintEvent(QPaintEvent *event)
{
    QStyleOption opt;
    opt.initFrom(this);
    QPainter p(this);
    style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
}

void PanelContainer::onCollapseButtonClicked()
{
	setCollapsed(!m_collapsed);
}

void PanelContainer::onFloatingButtonClicked()
{
	// TODO 浮动按钮点击事件
}
