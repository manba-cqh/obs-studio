#pragma once

#include <QPixmap>
#include <QString>
#include <QFormLayout>
#include <QLabel>

#define BUTTON_QSS_STYLE(normal_icon, hover_icon, pressed_icon) \
    QString("QPushButton { border-image: url(:/images/%1); }" \
            "QPushButton:hover { border-image: url(:/images/%2); }" \
            "QPushButton:pressed { border-image: url(:/images/%3); }") \
        .arg(normal_icon) \
        .arg(hover_icon) \
        .arg(pressed_icon)

#define BUTTON_CHECKABLE_QSS_STYLE(normal_icon, hover_icon, pressed_icon, checked_icon, checked_hover_icon, checked_pressed_icon) \
    QString("QPushButton { border-image: url(:/images/%1); }" \
            "QPushButton:hover { border-image: url(:/images/%2); }" \
            "QPushButton:pressed { border-image: url(:/images/%3); }" \
            "QPushButton:checked { border-image: url(:/images/%4); }" \
            "QPushButton:checked:hover { border-image: url(:/images/%5); }" \
            "QPushButton:checked:pressed { border-image: url(:/images/%6); }") \
        .arg(normal_icon) \
        .arg(hover_icon) \
        .arg(pressed_icon) \
        .arg(checked_icon) \
        .arg(checked_hover_icon) \
        .arg(checked_pressed_icon)

#define BUTTON_TRANSPARENT_QSS_STYLE(font_size) \
    QString("QPushButton { background: transparent; color: #FFFFFFFF; font-size: %1px; font-weight: medium; border: none; text-align: center; }") \
        .arg(font_size)

void setFormLayoutLabelWidth(QFormLayout *layout, int minWidth);