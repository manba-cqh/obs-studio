#pragma once

#include <QPushButton>
#include <QString>

#include "CustomToolTip.hpp"

class CenterToolTipButton : public QPushButton
{
	Q_OBJECT

public:
	enum class ToolTipPosition { Above, Below };

	explicit CenterToolTipButton(const QString &tipText, QWidget *parent = nullptr);
	~CenterToolTipButton() override;

	void setToolTipPosition(ToolTipPosition pos);
	ToolTipPosition toolTipPosition() const { return m_tooltipPosition; }
	void setToolTipText(const QString &text) { m_tooltip->setText(text); }

protected:
	void enterEvent(QEnterEvent *event) override;
	void leaveEvent(QEvent *event) override;

private:
	CustomToolTip *m_tooltip = nullptr;
	ToolTipPosition m_tooltipPosition = ToolTipPosition::Below;
};

