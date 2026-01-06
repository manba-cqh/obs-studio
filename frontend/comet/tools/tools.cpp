#include "tools.hpp"

void setFormLayoutLabelWidth(QFormLayout *layout, int minWidth)
{
	for (int i = 0; i < layout->rowCount(); ++i) {
		QLayoutItem *item = layout->itemAt(i, QFormLayout::LabelRole);
		if (item && item->widget()) {
			QLabel *label = qobject_cast<QLabel*>(item->widget());
			if (label) {
				label->setMinimumWidth(minWidth);
			}
		}
	}
}