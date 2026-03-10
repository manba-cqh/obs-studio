#include "PanelHeaderWidget.hpp"
#include "tools.hpp"
#include <QPainter>
#include <QPainterPath>
#include <QLabel>
#include <QWidget>
#include <QDockWidget>

PanelHeaderWidget::PanelHeaderWidget(const QString &title, QWidget *parent)
	: QWidget(parent)
	, m_title(title)
{
	setAutoFillBackground(false);

	m_headerLayout = new QHBoxLayout(this);
	m_headerLayout->setContentsMargins(15, 0, 15, 0);
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

	// 浮动按钮（浮动时显示关闭图标，点击返回主窗体）
	m_floatingButton = new QPushButton(this);
	m_floatingButton->setFixedSize(24, 24);
	m_floatingButton->setStyleSheet(BUTTON_QSS_STYLE("float.svg", "float_hover.svg", "float_hover.svg"));
	m_floatingButton->setToolTip("浮动");
	connect(m_floatingButton, &QPushButton::clicked, this, &PanelHeaderWidget::onFloatingButtonClicked);
	m_headerLayout->addWidget(m_floatingButton);
}

PanelHeaderWidget::~PanelHeaderWidget()
{
}

QSize PanelHeaderWidget::sizeHint() const
{
	return QSize(width(), 40);
}

QSize PanelHeaderWidget::minimumSizeHint() const
{
	return QSize(width(), 40);
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
	if (!m_headerLayout || !widget)
		return;
	const int insertIndex = 4;
	int count = m_headerLayout->count();
	if (insertIndex < 0 || insertIndex > count)
		return;
	m_headerLayout->insertWidget(insertIndex, widget);
}

void PanelHeaderWidget::setCollapseButtonChecked(bool checked)
{
	if (m_collapseButton) {
		m_collapseButton->setChecked(checked);
	}
}

void PanelHeaderWidget::setDockWidget(QDockWidget *dock)
{
	if (m_dockWidget == dock)
		return;
	if (m_dockWidget) {
		m_dockWidget->disconnect(this);
	}
	m_dockWidget = dock;
	if (m_dockWidget) {
		connect(m_dockWidget, &QDockWidget::topLevelChanged, this, &PanelHeaderWidget::updateFloatingButtonAppearance);
		updateFloatingButtonAppearance(m_dockWidget->isFloating());
	}
}

void PanelHeaderWidget::updateFloatingButtonAppearance(bool floating)
{
	if (!m_floatingButton)
		return;
	if (floating) {
		m_floatingButton->setStyleSheet(BUTTON_QSS_STYLE("close.svg", "close_hover.svg", "close_hover.svg"));
		m_floatingButton->setToolTip("返回主窗口");
	} else {
		m_floatingButton->setStyleSheet(BUTTON_QSS_STYLE("float.svg", "float_hover.svg", "float_hover.svg"));
		m_floatingButton->setToolTip("浮动");
	}
}

void PanelHeaderWidget::onCollapseButtonClicked(bool checked)
{
	// emit sigCollapseClicked();
	QWidget *parentWidget = this->parentWidget();
	if (!parentWidget) {
		return;
	}

	if (checked) {
		m_preParentSize = parentWidget->size();
		m_preParentMinimumSize = parentWidget->minimumSize();
		m_preParentMaximumSize = parentWidget->maximumSize();
		parentWidget->setMinimumHeight(this->height() + 10);
		parentWidget->setMaximumHeight(this->height() + 10);
		// parentWidget->resize(m_preParentSize.width(), this->height() + 10);
	}
	else {
		parentWidget->setMinimumHeight(m_preParentMinimumSize.height());
		parentWidget->setMaximumHeight(m_preParentMaximumSize.height());
		parentWidget->resize(m_preParentSize.width(), m_preParentSize.height());
	}
}

void PanelHeaderWidget::onFloatingButtonClicked()
{
	if (m_dockWidget && m_dockWidget->isFloating()) {
		emit sigFloating(false);  // 浮动中：点击返回主窗体
	} else {
		emit sigFloating(true);   // 停靠中：点击分离
	}
}

void PanelHeaderWidget::paintEvent(QPaintEvent *event)
{
	Q_UNUSED(event);
	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);
	p.setRenderHint(QPainter::SmoothPixmapTransform);

	const int radius = 4;
	QRect r = rect();

	// 左上/右上圆角路径，不绘制下边框（向下延伸1px与下方内容无缝衔接）
	QPainterPath path;
	path.moveTo(r.x(), r.bottom() + 1);
	path.lineTo(r.x(), r.y() + radius);
	path.quadTo(r.x(), r.y(), r.x() + radius, r.y());
	path.lineTo(r.right() - radius, r.y());
	path.quadTo(r.right(), r.y(), r.right(), r.y() + radius);
	path.lineTo(r.right(), r.bottom() + 1);
	path.closeSubpath();

	p.fillPath(path, QColor(34, 34, 50, static_cast<int>(255 * 0.8)));
}

