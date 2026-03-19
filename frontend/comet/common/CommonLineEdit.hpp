#pragma once

#include <QLineEdit>

class CommonLineEdit : public QLineEdit
{
public:
    explicit CommonLineEdit(bool configStyle = false, QWidget *parent = nullptr)
        : QLineEdit(parent)
    {
        setAttribute(Qt::WA_StyledBackground, true);
        setFixedHeight(30);
        if (configStyle) {
            setStyleSheet(
                "QLineEdit {"
                "    background-color: #3C3C4D;"
                "    color: #EEEFFF;"
                "    border: 1px solid #454558;"
                "    border-radius: 5px;"
                "    padding: 6px 10px;"
                "    font-size: 14px;"
                "}"
                "QLineEdit:hover {"
                "    border-color: #5370FF;"
                "}"
                "QLineEdit:focus {"
                "    border-color: #5370FF;"
                "    outline: none;"
                "}"
                "QLineEdit:disabled {"
                "    background-color: #1F1F2C;"
                "    color: #808080;"
                "    border-color: #2C2C3C;"
                "}"
            );
        } else {
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
    }
};