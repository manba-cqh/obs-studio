#include "PanelHeaderWidget.hpp"
#include "tools.hpp"
#include <QWidget>
#include <QLabel>

PanelHeaderWidget::PanelHeaderWidget(const QString &title, QWidget *parent)
	: QWidget(parent)
	, m_title(title)
{
	setFixedHeight(40);
    setProperty("pannel_widget", true);
	m_headerLayout = new QHBoxLayout(this);
	m_headerLayout->setContentsMargins(0, 0, 0, 0);
	m_headerLayout->setSpacing(0);

	// 折叠按钮
	m_collapseButton = new QPushButton(this);
	m_collapseButton->setFixedSize(24, 24);
	m_collapseButton->setCheckable(true);
	m_collapseButton->setChecked(false);
	m_collapseButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("drop_down.svg", "drop_down_hover.svg", "drop_down_hover.svg", "drop_down_expanded.png", "drop_down_expanded_hover.png", "drop_down_expanded_hover.png"));
	connect(m_collapseButton, &QPushButton::clicked, this, &PanelHeaderWidget::onCollapseButtonClicked);
	m_headerLayout->addWidget(m_collapseButton);
	m_headerLayout->addSpacing(4);

	// 标题
	m_titleLabel = new QLabel(this);
	m_titleLabel->setText(m_title);
	m_titleLabel->setProperty("label_15_medium", true);
	m_headerLayout->addWidget(m_titleLabel);

	m_headerLayout->addStretch();

	m_headerLayout->addSpacing(8);
	QWidget *separator = new QWidget(this);
	separator->setFixedSize(1, 10);
	separator->setStyleSheet("background-color: rgba(255, 255, 255, 125);");
	m_headerLayout->addWidget(separator);
	m_headerLayout->addSpacing(8);

	// 浮动按钮
	m_floatingButton = new QPushButton(this);
	m_floatingButton->setFixedSize(24, 24);
	m_floatingButton->setStyleSheet(BUTTON_QSS_STYLE("float.svg", "float_hover.svg", "float_hover.svg"));
	m_floatingButton->setCheckable(true);
	m_floatingButton->setChecked(false);
	connect(m_floatingButton, &QPushButton::clicked, this, &PanelHeaderWidget::onFloatingButtonClicked);
	m_headerLayout->addWidget(m_floatingButton);
}

PanelHeaderWidget::~PanelHeaderWidget()
{
}

void PanelHeaderWidget::setTitle(const QString &title)
{
	m_title = title;
	if (m_titleLabel) {
		m_titleLabel->setText(title);
	}
}

QString PanelHeaderWidget::title() const
{
	return m_title;
}

void PanelHeaderWidget::setHeaderOperWidget(QWidget *widget)
{
	if (m_headerLayout && widget) {
		// 在标题后面插入操作控件（索引为3，折叠按钮0，间距1，标题2，操作控件3）
		m_headerLayout->insertWidget(3, widget);
	}
}

void PanelHeaderWidget::setCollapseButtonChecked(bool checked)
{
	if (m_collapseButton) {
		m_collapseButton->setChecked(checked);
	}
}

void PanelHeaderWidget::onCollapseButtonClicked()
{
	emit sigCollapseClicked();
}

void PanelHeaderWidget::onFloatingButtonClicked()
{
	if (m_floatingButton) {
		emit sigFloating(m_floatingButton->isChecked());
	}
}

