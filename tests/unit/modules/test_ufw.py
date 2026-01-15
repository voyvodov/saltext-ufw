import pytest
import salt.modules.test as testmod

import saltext.ufw.modules.ufw as ufw_module


@pytest.fixture
def configure_loader_modules():
    module_globals = {
        "__salt__": {"test.echo": testmod.echo},
    }
    return {
        ufw_module: module_globals,
    }
