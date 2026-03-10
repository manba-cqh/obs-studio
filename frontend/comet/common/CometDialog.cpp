#include "CometDialog.hpp"

#include <QGridLayout>
#include <QPainter>
#include <QPainterPath>
#include <QRegion>
#include <QResizeEvent>

CometDialog::CometDialog(const QString &title, QWidget *parent,
                        DialogTitleBar::CornerStyle cornerStyle, bool deferLayout)
	: QDialog(parent)
	, m_container(nullptr)
	, m_contentWidget(nullptr)
	, m_titleBar(nullptr)
	, m_backgroundColor("#1F1F2C")
	, m_cornerRadius(5)
	, m_contentMargins(15, 15, 15, 15)
	, m_deferLayout(deferLayout)
{
	setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
	setAttribute(Qt::WA_TranslucentBackground);
	setModal(true);

	m_container = new QWidget(this);
	m_container->setAttribute(Qt::WA_TranslucentBackground);
	m_container->setStyleSheet("background: transparent;");

	QVBoxLayout *containerLayout = new QVBoxLayout(m_container);
	containerLayout->setContentsMargins(0, 0, 0, 0);
	containerLayout->setSpacing(0);

	m_titleBar = new DialogTitleBar(this, m_container, title, cornerStyle);
	containerLayout->addWidget(m_titleBar, 0);

	m_contentWidget = new QWidget(m_container);
	m_contentWidget->setAttribute(Qt::WA_TranslucentBackground);
	m_contentWidget->setStyleSheet("background: transparent;");
	QVBoxLayout *contentLayout = new QVBoxLayout(m_contentWidget);
	contentLayout->setContentsMargins(m_contentMargins);
	contentLayout->setSpacing(0);
	containerLayout->addWidget(m_contentWidget, 1);

	if (!m_deferLayout) {
		QVBoxLayout *dialogLayout = new QVBoxLayout(this);
		dialogLayout->setContentsMargins(0, 0, 0, 0);
		dialogLayout->addWidget(m_container, 1);
	}
}

CometDialog::~CometDialog() {}

void CometDialog::setDialogSize(int w, int h)
{
	setFixedSize(w, h);
	updateMask();
}

void CometDialog::setBackgroundColor(const QColor &color)
{
	m_backgroundColor = color;
	update();
}

void CometDialog::setCornerRadius(int radius)
{
	m_cornerRadius = radius;
	updateMask();
	update();
}

void CometDialog::setContentMargins(int left, int top, int right, int bottom)
{
	m_contentMargins = QMargins(left, top, right, bottom);
	if (m_contentWidget && m_contentWidget->layout()) {
		m_contentWidget->layout()->setContentsMargins(m_contentMargins);
	}
}

void CometDialog::updateMask()
{
	if (testAttribute(Qt::WA_TranslucentBackground)) {
		clearMask();
	} else {
		// Non-translucent top-level windows need a shape mask to avoid dark square corners.
		QPainterPath path;
		path.addRoundedRect(QRectF(rect()).adjusted(0, 0, -1, -1), m_cornerRadius, m_cornerRadius);
		setMask(QRegion(path.toFillPolygon().toPolygon()));
	}
	update();
}

void CometDialog::finishCometLayout()
{
	if (!m_deferLayout || !m_container)
		return;
	QLayout *originalLayout = layout();
	QVBoxLayout *contentLayout = qobject_cast<QVBoxLayout *>(m_contentWidget->layout());
	if (originalLayout && contentLayout) {
		QList<QLayoutItem *> items;
		while (originalLayout->count() > 0) {
			items.append(originalLayout->takeAt(0));
		}
		for (QLayoutItem *item : items) {
			if (item->widget()) {
				contentLayout->addWidget(item->widget());
				delete item;
			} else if (item->layout()) {
				// item IS the QLayout (QLayout extends QLayoutItem).
				// Wrap in a QWidget so that setLayout() reparents all
				// child widgets into the CometDialog hierarchy.
				QWidget *wrapper = new QWidget(m_contentWidget);
				wrapper->setSizePolicy(QSizePolicy::Preferred,
						       QSizePolicy::Expanding);
				wrapper->setLayout(item->layout());
				contentLayout->addWidget(wrapper);
				// setLayout() took ownership — do NOT delete item
			} else {
				contentLayout->addItem(item);
			}
		}
		delete originalLayout;
	}
	setCometLayout();
	m_deferLayout = false;
}

void CometDialog::setCometLayout()
{
	if (!m_container)
		return;
	QVBoxLayout *dialogLayout = new QVBoxLayout(this);
	dialogLayout->setContentsMargins(0, 0, 0, 0);
	dialogLayout->addWidget(m_container, 1);
}

void CometDialog::paintEvent(QPaintEvent *event)
{
	Q_UNUSED(event);
	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);
	p.setRenderHint(QPainter::SmoothPixmapTransform);
	const QRectF frameRect = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
	QPainterPath framePath;
	framePath.addRoundedRect(frameRect, m_cornerRadius, m_cornerRadius);

	p.setPen(Qt::NoPen);
	p.setBrush(m_backgroundColor);
	p.drawPath(framePath);

	p.setPen(QPen(QColor(255, 255, 255, 26), 1)); // 1px solid rgba(255,255,255,0.1)
	p.setBrush(Qt::NoBrush);
	p.drawPath(framePath);
}

void CometDialog::resizeEvent(QResizeEvent *event)
{
	QDialog::resizeEvent(event);
	updateMask();
}
