#pragma once

#include <QComboBox>
#include <QStyledItemDelegate>

/** 不绘制 item 焦点虚线框的 delegate */
class NoFocusItemDelegate : public QStyledItemDelegate
{
public:
    explicit NoFocusItemDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        QStyleOptionViewItem opt = option;
        opt.state &= ~QStyle::State_HasFocus;  // 去除焦点状态，避免绘制虚线框
        QStyledItemDelegate::paint(painter, opt, index);
    }
};

class CommonComboBox : public QComboBox
{
public:
    explicit CommonComboBox(bool isTransparent = false, QWidget *parent = nullptr)
        : QComboBox(parent)
    {
        setAttribute(Qt::WA_StyledBackground, true);
        setItemDelegate(new NoFocusItemDelegate(this));
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
            "    outline: none;"
            "}"
            "QComboBox QAbstractItemView::item {"
            "    padding: 6px 12px;"
            "    border-radius: 2px;"
            "    outline: none;"
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