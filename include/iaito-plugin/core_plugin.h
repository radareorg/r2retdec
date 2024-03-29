/**
 * @file include/iaito-plugin/core_plugin.h
 * @brief Main module of the retdec-iaito-plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef RETDEC_R2PLUGIN_CORE_PLUGIN_H
#define RETDEC_R2PLUGIN_CORE_PLUGIN_H

#include <QObject>
#include <QtPlugin>
#include <plugins/IaitoPlugin.h>

#include "Decompiler.h"

class RetDecPlugin : public QObject, IaitoPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.radare.iaito.plugins.r2retdec")
    Q_INTERFACES(IaitoPlugin)

    class RetDec: public Decompiler {
    public:
	RetDec(QObject *parent = nullptr);
	void decompileAt(RVA addr) override;
    };

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;
    void registerDecompilers() override;

    QString getName() const override {
	    return "RetDec Decompiler (retdec-r2plugin)";
    }

    QString getAuthor() const override {
	    return "Avast";
    }

    QString getDescription() const override {
	    return "RetDec plugin for Iaito";
    }

    QString getVersion() const override {
	    return "0.3";
    }
};


#endif // RETDEC_R2PLUGIN_CORE_PLUGIN_H
