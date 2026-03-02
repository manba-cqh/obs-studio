#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

class CollapsibleGroupBox : public QWidget
{
	Q_OBJECT

public:
	explicit CollapsibleGroupBox(const QString &title, QWidget *parent = nullptr);
	~CollapsibleGroupBox();

	void setTitle(const QString &title);
	QString title() const;

	void setExpanded(bool expanded);
	bool isExpanded() const;

	QBoxLayout *contentLayout() { return m_contentLayout; }

signals:
	void toggled(bool expanded);

protected:
	void setupHeader();
	bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
	void onHeaderClicked();
	void onChevronClicked();

private:
	QString m_title;
	bool m_expanded;
	QWidget *m_headerWidget;
	QLabel *m_titleLabel;
	QPushButton *m_chevronButton;
	QWidget *m_contentWidget;
	QVBoxLayout *m_contentLayout;
};
