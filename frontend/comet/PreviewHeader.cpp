#include "PreviewHeader.hpp"

PreviewHeader::PreviewHeader(QWidget *parent)
    : QWidget(parent)
{
    initUI();
}

PreviewHeader::~PreviewHeader()
{
}

void PreviewHeader::initUI()
{
    setFixedHeight(42);
}