// Test basic class functionality
class Animal {
    constructor(name) {
        this.name = name;
    }

    speak() {
        return this.name + ' makes a sound';
    }

    static getType() {
        return 'animal';
    }
}

const dog = new Animal('Dog');
console.log(dog.speak());
console.log(Animal.getType());