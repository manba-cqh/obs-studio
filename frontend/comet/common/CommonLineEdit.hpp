#pragma once

#include <QLineEdit>

class CommonLineEdit : public QLineEdit
{
public:
    explicit CommonLineEdit(QWidget *parent = nullptr)
        : QLineEdit(parent)
    {
        setAttribute(Qt::WA_StyledBackground, true);
        setFixedHeight(30);
        setStyleSheet(
            "QLineEdit {"
            "    background-color: #3C3C4D;"
            "    color: #EEEFFF;"
            "    border-radius: 5px;"
            "    padding: 6px 10px;"
            "    font-size: 14px;"
            "}"
            "QLineEdit:hover {"
            "    border: 1px solid #5370FF;"
            "}"
            "QLineEdit:focus {"
            "    border: 1px solid #5370FF;"
            "    outline: none;"
            "}"
            "QLineEdit:disabled {"
            "    background-color: #1F1F2C;"
            "    color: #808080;"
            "    border: 1px solid #2C2C3C;"
            "}"
        );
    }
};