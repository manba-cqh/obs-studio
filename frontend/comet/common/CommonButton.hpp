#pragma once

#include <QPushButton>
#include <QString>

class CommonButton : public QPushButton
{
public:
    explicit CommonButton(const QString &text, QWidget *parent = nullptr)
        : QPushButton(text, parent)
    {
        init();
    }
    CommonButton(QWidget *parent = nullptr)
        : QPushButton(parent)
    {
        init();
    }
    void init()
    {
        setAttribute(Qt::WA_StyledBackground, true);
        setStyleSheet(
            "QPushButton {"
            "    background-color: #3C3C4D;"
            "    color: #FFFFFFFF;"
            "    border: none;"
            "    border-radius: 5px;"
            "    font-size: 14px;"
            "    font-weight: medium;"
            "}"
            "QPushButton:hover {"
            "    background-color: #5370FF;"
            "}"
            "QPushButton:pressed {"
            "    background-color: #5370FF;"
            "}"
        );
    }
};