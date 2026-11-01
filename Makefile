THEOS ?= $(HOME)/theos
ARCHS = arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide
PACKAGE_VERSION = 1.41.1

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = AppleSigner
AppleSigner_FILES = SigningPlanExporter.m DEREntitlementsDecoder.m EntitlementsProfileComparator.m EntitlementsAudit.m main.m AppDelegate.m ViewController.m ProfileInspector.m IPAInspector.m IPAExtractor.m SignatureAudit.m SigningPreparation.m MachOSignatureInspector.m CodeDirectoryBuilder.m SuperBlobBuilder.m MachOSignatureStager.m SigningIdentityVerifier.m CMSPreflight.m CMSDetachedBuilder.m CMSDetachedVerifier.m
AppleSigner_FRAMEWORKS = UIKit UniformTypeIdentifiers Security
AppleSigner_LIBRARIES = z
AppleSigner_CFLAGS = -fobjc-arc -Wno-error=nullability-completeness
AppleSigner_CODESIGN_FLAGS = -Sroothide.entitlements
AppleSigner_INSTALL_PATH = /Applications

include $(THEOS_MAKE_PATH)/application.mk

# Normalize RootHide's loader paths after Theos stages the app but before
# dpkg packages it. Duplicate LC_RPATH commands make dyld abort at launch.
after-AppleSigner-stage::
	python3 scripts/fix-roothide-rpaths.py "$(THEOS_STAGING_DIR)$(AppleSigner_INSTALL_PATH)/AppleSigner.app/AppleSigner" "roothide.entitlements"

after-install::
	install.exec "uicache -p /Applications/AppleSigner.app || true"
