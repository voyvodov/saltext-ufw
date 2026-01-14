import pytest
import salt.modules.test as testmod

import saltext.ufw.modules.ufw as ufw_module
import saltext.ufw.states.ufw as ufw_state


@pytest.fixture
def configure_loader_modules():
    return {
        ufw_module: {
            "__salt__": {
                "test.echo": testmod.echo,
            },
        },
        ufw_state: {
            "__salt__": {
                "ufw.example_function": ufw_module.example_function,
            },
        },
    }
