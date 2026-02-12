/******************************************************************************
    Copyright (C) 2023 by Lain Bailey <lain@obsproject.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
******************************************************************************/

#include "NameDialog.hpp"

#include <OBSApp.hpp>

#include "comet/common/MovableWidget.hpp"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFile>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPaintEvent>
#include <QPainter>
#include <QPushButton>
#include <QStyleOption>
#include <QVBoxLayout>

#include "moc_NameDialog.cpp"

NameDialog::NameDialog(QWidget *parent) : QDialog(parent)
{
	installEventFilter(CreateShortcutFilter());
	setModal(true);
	setWindowModality(Qt::WindowModality::WindowModal);
	setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
	setAttribute(Qt::WA_TranslucentBackground, false);
	setAutoFillBackground(true);
	setObjectName("NameDialog");
	setFixedWidth(400);
	setMinimumHeight(120);

	QFile styleFile(":/property_styles.qss");
	if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
		QString style = QString::fromUtf8(styleFile.readAll());
		style.replace("OBSBasicProperties", "NameDialog");
		setStyleSheet(style);
		styleFile.close();
	}

	QWidget *container = new QWidget(this);
	container->setStyleSheet("QWidget { background-color: #1F1F2C; border-radius: 5px; }");

	QVBoxLayout *containerLayout = new QVBoxLayout(container);
	containerLayout->setContentsMargins(0, 0, 0, 0);
	containerLayout->setSpacing(0);

	MovableWidget *titleBar = new MovableWidget(this, container);
	titleBar->setStyleSheet("MovableWidget { background-color: #2C2C3C; border-radius: 5px 5px 0 0; }");
	titleBar->setFixedHeight(50);
	QHBoxLayout *titleLayout = new QHBoxLayout(titleBar);
	titleLayout->setContentsMargins(15, 13, 15, 13);
	titleLayout->setSpacing(0);

	m_titleLabel = new QLabel(titleBar);
	m_titleLabel->setTextFormat(Qt::PlainText);
	m_titleLabel->setStyleSheet(
		"QLabel { color: #FFFFFF; font-size: 15px; font-weight: bold; background: transparent; border: none; padding: 0px; }");
	titleLayout->addWidget(m_titleLabel, 0, Qt::AlignVCenter);
	titleLayout->addStretch();

	QPushButton *closeBtn = new QPushButton(titleBar);
	closeBtn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	closeBtn->setFixedSize(24, 24);
	closeBtn->setCursor(Qt::PointingHandCursor);
	closeBtn->setStyleSheet(
		"QPushButton {"
		"    border: none;"
		"    background: transparent;"
		"    background-image: url(:/images/close.svg);"
		"    background-repeat: no-repeat;"
		"    background-position: center;"
		"}"
		"QPushButton:hover { background-image: url(:/images/close_hover.svg); }"
		"QPushButton:pressed { background-image: url(:/images/close_pressed.svg); }"
	);
	connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
	titleLayout->addWidget(closeBtn, 0, Qt::AlignVCenter);
	containerLayout->addWidget(titleBar);

	QVBoxLayout *contentLayout = new QVBoxLayout();
	contentLayout->setContentsMargins(15, 15, 15, 15);
	contentLayout->setSpacing(12);

	label = new QLabel(container);
	label->setText("Set Text");
	label->setStyleSheet("QLabel { color: #EEEEFF; background: transparent; }");
	contentLayout->addWidget(label);

	userText = new QLineEdit(container);
	contentLayout->addWidget(userText);

	checkbox = new QCheckBox(container);
	checkbox->setStyleSheet("QCheckBox { color: #EEEEFF; background: transparent; }");
	contentLayout->addWidget(checkbox);

	QDialogButtonBox *buttonbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	buttonbox->setCenterButtons(true);
	contentLayout->addWidget(buttonbox);

	containerLayout->addLayout(contentLayout);

	QVBoxLayout *dialogLayout = new QVBoxLayout(this);
	dialogLayout->setContentsMargins(0, 0, 0, 0);
	dialogLayout->addWidget(container);

	userText->setFocus();
	connect(buttonbox, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttonbox, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void NameDialog::setWindowTitle(const QString &title)
{
	QDialog::setWindowTitle(title);
	if (m_titleLabel)
		m_titleLabel->setText(title);
}

void NameDialog::paintEvent(QPaintEvent *event)
{
	QStyleOption opt;
	opt.initFrom(this);
	QPainter p(this);
	style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
	QDialog::paintEvent(event);
}

static bool IsWhitespace(char ch)
{
	return ch == ' ' || ch == '\t';
}

static void CleanWhitespace(std::string &str)
{
	while (str.size() && IsWhitespace(str.back()))
		str.erase(str.end() - 1);
	while (str.size() && IsWhitespace(str.front()))
		str.erase(str.begin());
}

bool NameDialog::AskForName(QWidget *parent, const QString &title, const QString &text, std::string &userTextInput,
			    const QString &placeHolder, int maxSize)
{
	if (maxSize <= 0 || maxSize > 32767)
		maxSize = 170;

	NameDialog dialog(parent);
	dialog.setWindowTitle(title);

	dialog.checkbox->setHidden(true);
	dialog.label->setText(text);
	dialog.userText->setMaxLength(maxSize);
	dialog.userText->setText(placeHolder);
	dialog.userText->selectAll();

	if (dialog.exec() != DialogCode::Accepted) {
		return false;
	}
	userTextInput = dialog.userText->text().toUtf8().constData();
	CleanWhitespace(userTextInput);
	return true;
}

bool NameDialog::AskForNameWithOption(QWidget *parent, const QString &title, const QString &text,
				      std::string &userTextInput, const QString &optionLabel, bool &optionChecked,
				      const QString &placeHolder)
{
	NameDialog dialog(parent);
	dialog.setWindowTitle(title);

	dialog.label->setText(text);
	dialog.userText->setMaxLength(170);
	dialog.userText->setText(placeHolder);
	dialog.checkbox->setText(optionLabel);
	dialog.checkbox->setChecked(optionChecked);

	if (dialog.exec() != DialogCode::Accepted) {
		return false;
	}

	userTextInput = dialog.userText->text().toUtf8().constData();
	CleanWhitespace(userTextInput);
	optionChecked = dialog.checkbox->isChecked();
	return true;
}
