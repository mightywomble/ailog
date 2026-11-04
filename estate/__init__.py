"""The estate: the swarm's intent file, its stack files, and the CI that ships them.

AILog monitors hosts.  It should not *become* the thing that mutates them from
inside a monitoring app - the estate already has a pipeline that does that well:

    wizard.yaml              intent: image, version, ports, url, replicas
    stacks/<name>/stack.yml   the runnable definition (rendered from the intent)
    .gitea/workflows/        mirror.yml caches the image into zot, ship.yml
                             builds/prunes and `docker stack deploy`s the stack

So an "update" here is not a docker command.  It is a small, reviewable commit:
move one service's version in the three places it lives, push it to `dev` (which
makes mirror.yml copy the new image into zot), open the PR to `main`, merge it,
and report the run.  Execution stays in CI, on the runners that already hold the
zot credentials and the manager socket - the thing this app deliberately does
not have.

That is why the update dialog streams *CI jobs* rather than docker output, and
why a swarm container's update goes through here instead of
`docker service update`: the running image must stay the image git says it is.
"""

from .routes import estate_bp

__all__ = ['estate_bp']
