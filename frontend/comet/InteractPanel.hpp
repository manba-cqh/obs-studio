#ifndef INTERACTPANEL_HPP
#define INTERACTPANEL_HPP

#include <QWidget>

#include "PanelContainer.hpp"

class InteractPanel : public PanelContainer
{
    Q_OBJECT
public:
    explicit InteractPanel(QWidget *parent = nullptr);
    ~InteractPanel();

private:
    void initUI();
};

#endif // INTERACTPANEL_HPP  