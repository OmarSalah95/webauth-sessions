exports.seed = function(knex, Promise) {
  // Deletes ALL existing entries
  return knex('users')
    .truncate()
    .then(function() {
      // Inserts seed entries
      return knex('users').insert([
        { id: 1, username: 'omzz35', password: 'to bo hashed' },
        { id: 2, username: 'kingweirdo', password: 'to bo hashed' },
        { id: 3, username: 'alejandro', password: 'to bo hashed' }
      ]);
    });
};
