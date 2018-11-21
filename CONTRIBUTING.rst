When developping on flameclient, do not forget to check code quality with the
`./checkcode` command, and then check you did not brake anything by running
`python -m unittest discover -v`.

To create flame modules you need to create a module with a class which
inheritates from `flameclient.resources.ResourceManager`

You need to implement the `api_resources` property and the `get_hot_resources()`
method (read their docstring for more information).
If you want you can also implement the `add_arguments(parser=None)` method to
add your own module's command line arguments.
You can also implement the `post_process()`,
`post_process_hot_resources(resources)`, `post_process_heat_template(template)` and/or
`post_process_adoption_data(adoption_data)` methods to perform
post processing after the generator's `extract_data` method was called
(read their docstring for more information). This allows you to modify results
before rendering the template.
These post processing methods are not threaded and are executed in order of the
managers' `post_priority` attribute (defaults to 100).

Then, you need to add in your package's `setup.py` or `setup.cfg` an
'openstack_flame' entry point pointing to the module file where your subclass
of `flameclient.resources.ResourceManager` is defined.

Once your package installed, flame will automatically discover all
'openstack_flame' entry points to load the corresponding modules, and all
loaded modules having a `flameclient.resources.ResourceManager` subclass will
have this subclass detected and added tho the list of managers.
