#ifndef INTERACTPANEL_HPP
#define INTERACTPANEL_HPP

#include <QWidget>

#include "common/PanelContainer.hpp"

class InteractPanel : public PanelContainer
{
    Q_OBJECT
public:
    explicit InteractPanel(QWidget *parent = nullptr);
    ~InteractPanel();
};

#endif // INTERACTPANEL_HPP  