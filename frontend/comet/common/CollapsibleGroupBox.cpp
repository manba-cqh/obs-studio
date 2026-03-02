#include "CollapsibleGroupBox.hpp"
#include "tools.hpp"
#include <QFrame>
#include <QMouseEvent>

CollapsibleGroupBox::CollapsibleGroupBox(const QString &title, QWidget *parent)
	: QWidget(parent)
	, m_title(title)
	, m_expanded(false)
{
	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);

	setupHeader();
	mainLayout->addWidget(m_headerWidget);

	m_contentWidget = new QWidget(this);
	m_contentLayout = new QVBoxLayout(m_contentWidget);
	m_contentLayout->setContentsMargins(0, 12, 0, 0);
	m_contentLayout->setSpacing(0);
	mainLayout->addWidget(m_contentWidget);

	m_contentWidget->setVisible(m_expanded);
}

CollapsibleGroupBox::~CollapsibleGroupBox()
{
}

void CollapsibleGroupBox::setupHeader()
{
	m_headerWidget = new QFrame(this);
	m_headerWidget->setObjectName("collapsibleGroupBoxHeader");
	m_headerWidget->setCursor(Qt::PointingHandCursor);
	m_headerWidget->setFixedHeight(40);

	QHBoxLayout *headerLayout = new QHBoxLayout(m_headerWidget);
	headerLayout->setContentsMargins(0, 0, 0, 0);
	headerLayout->setSpacing(6);

	m_titleLabel = new QLabel(m_title, m_headerWidget);
	m_titleLabel->setProperty("label_15_medium", true);
	m_titleLabel->setStyleSheet("color: #FFFFFFFF;");
	headerLayout->addWidget(m_titleLabel);

	m_chevronButton = new QPushButton(m_headerWidget);
	m_chevronButton->setFixedSize(16, 16);
	m_chevronButton->setCheckable(true);
	m_chevronButton->setChecked(m_expanded);
	m_chevronButton->setCursor(Qt::PointingHandCursor);
	m_chevronButton->setStyleSheet(
		BUTTON_CHECKABLE_QSS_STYLE("drop_down.svg", "drop_down_hover.svg", "drop_down_hover.svg",
					   "drop_up.svg", "drop_up.svg", "drop_up.svg"));
	m_chevronButton->setFlat(true);
	headerLayout->addWidget(m_chevronButton);
	headerLayout->addStretch();

	connect(m_chevronButton, &QPushButton::clicked, this, &CollapsibleGroupBox::onChevronClicked);

	m_headerWidget->installEventFilter(this);
}

bool CollapsibleGroupBox::eventFilter(QObject *watched, QEvent *event)
{
	if (watched == m_headerWidget && event->type() == QEvent::MouseButtonPress) {
		QMouseEvent *me = static_cast<QMouseEvent *>(event);
		if (me && me->button() == Qt::LeftButton) {
			onHeaderClicked();
			return true;
		}
	}
	return QWidget::eventFilter(watched, event);
}

void CollapsibleGroupBox::onHeaderClicked()
{
	setExpanded(!m_expanded);
}

void CollapsibleGroupBox::onChevronClicked()
{
	setExpanded(m_chevronButton->isChecked());
}

void CollapsibleGroupBox::setTitle(const QString &title)
{
	m_title = title;
	if (m_titleLabel) {
		m_titleLabel->setText(title);
	}
}

QString CollapsibleGroupBox::title() const
{
	return m_title;
}

void CollapsibleGroupBox::setExpanded(bool expanded)
{
	if (m_expanded == expanded) {
		return;
	}
	m_expanded = expanded;
	m_contentWidget->setVisible(expanded);
	if (m_chevronButton) {
		m_chevronButton->setChecked(expanded);
	}
	emit toggled(expanded);
}

bool CollapsibleGroupBox::isExpanded() const
{
	return m_expanded;
}
