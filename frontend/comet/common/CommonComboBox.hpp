#pragma once

#include <QComboBox>

class CommonComboBox : public QComboBox
{
public:
    explicit CommonComboBox(bool isTransparent = false, QWidget *parent = nullptr)
        : QComboBox(parent)
    {
        setAttribute(Qt::WA_StyledBackground, true);
        // TODO 全局设置样式表不生效
        setStyleSheet(QString(
            "QComboBox {"
            "    background-color: %1;"
            "    color: #EEEFFF;"
            "    border-radius: 5px;"
            "    padding: 6px 10px;"
            "    font-size: 14px;"
            "    font-weight: medium;"
            "}"
            "QComboBox:hover {"
            "    %2;"
            "}"
            "QComboBox:focus {"
            "    %3;"
            "    outline: none;"
            "}"
            "QComboBox::drop-down {"
            "    border: none;"
            "    width: 24px;"
            "    background: transparent;"
            "    subcontrol-origin: padding;"
            "    subcontrol-position: top right;"
            "}"
            "QComboBox::down-arrow {"
            "    image: url(:/images/drop_down.svg);"
            "}"
            "QComboBox QAbstractItemView {"
            "    background-color: #2C2C3C;"
            "    color: #FFFFFFFF;"
            "    border: 1px solid #454558;"
            "    border-radius: 4px;"
            "    selection-background-color: #5370FF;"
            "    selection-color: #FFFFFFFF;"
            "    padding: 4px;"
            "}"
            "QComboBox QAbstractItemView::item {"
            "    padding: 6px 12px;"
            "    border-radius: 2px;"
            "}"
            "QComboBox QAbstractItemView::item:hover {"
            "    background-color: #454558;"
            "}"
            "QComboBox QAbstractItemView::item:selected {"
            "    background-color: #5370FF;"
            "    color: #FFFFFFFF;"
            "}"
        ).arg(isTransparent ? "transparent" : "#3C3C4D")
        .arg(isTransparent ? "border: none;" : "border: 1px solid #5370FF;")
        .arg(isTransparent ? "border: none;" : "border: 1px solid #5370FF;"));
    }
};